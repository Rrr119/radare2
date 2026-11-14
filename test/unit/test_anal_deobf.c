#include <r_anal.h>
#include "minunit.h"
#include <string.h>

typedef struct {
	ut8 data[0x400];
	ut64 base;
	size_t size;
} FlatFixture;

static bool flat_read_at(RAnal *anal, ut64 addr, ut8 *buf, int len) {
	FlatFixture *fixture = anal->user;
	if (addr < fixture->base || len < 0 || addr + len > fixture->base + fixture->size) {
		return false;
	}
	memcpy (buf, fixture->data + (addr - fixture->base), len);
	return true;
}

static RAnal *flat_anal_new(FlatFixture *fixture) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "create RAnal");
	mu_assert_true (r_anal_use (anal, "x86"), "select x86");
	mu_assert_true (r_anal_set_bits (anal, 32), "select 32-bit x86");
	anal->read_at = flat_read_at;
	anal->user = fixture;
	return anal;
}

static RAnalBlock *flat_add_block(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 size) {
	RAnalBlock *block = r_anal_create_block (anal, addr, size);
	mu_assert_notnull (block, "create basic block");
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	return block;
}

static void flat_write_u32(FlatFixture *fixture, ut64 addr, ut32 value) {
	r_write_le32 (fixture->data + (addr - fixture->base), value);
}

static void flat_mov_eax_imm(FlatFixture *fixture, ut64 addr, ut32 value) {
	ut8 *p = fixture->data + (addr - fixture->base);
	p[0] = 0xb8;
	flat_write_u32 (fixture, addr + 1, value);
}

static void flat_mov_state_imm(FlatFixture *fixture, ut64 addr, ut32 value) {
	ut8 *p = fixture->data + (addr - fixture->base);
	p[0] = 0xc7;
	p[1] = 0x45;
	p[2] = 0xfc;
	flat_write_u32 (fixture, addr + 3, value);
}

static void flat_jmp32(FlatFixture *fixture, ut64 addr, ut64 target) {
	ut8 *p = fixture->data + (addr - fixture->base);
	p[0] = 0xe9;
	r_write_le32 (p + 1, (ut32)(target - (addr + 5)));
}

static RAnalBlock *flat_fcn_block(RAnalFunction *fcn, ut64 addr) {
	RAnalBlock **iter;
	RAnalBlock *block;
	R_VEC_FOREACH (&fcn->bbs, iter) {
		block = *iter;
		if (block->addr == addr) {
			return block;
		}
	}
	return NULL;
}

static bool flat_dispatcher_switch(RAnalBlock *dispatcher, ut64 default_addr) {
	dispatcher->switch_op = r_anal_switch_op_new (dispatcher->addr,
		UT64_MAX, 0, default_addr);
	return dispatcher->switch_op != NULL;
}

bool test_anal_deobf_flatten_register_state(void) {
	FlatFixture fixture = {
		.base = 0x1000,
		.size = sizeof (fixture.data),
	};
	const ut64 entry_addr = 0x1000;
	const ut64 case_a = 0x1010;
	const ut64 case_b = 0x1020;
	const ut64 exit_addr = 0x1030;
	const ut64 dispatcher_addr = 0x1040;

	flat_mov_eax_imm (&fixture, entry_addr, 1);
	flat_jmp32 (&fixture, entry_addr + 5, dispatcher_addr);
	flat_mov_eax_imm (&fixture, case_a, 2);
	flat_jmp32 (&fixture, case_a + 5, dispatcher_addr);
	flat_mov_eax_imm (&fixture, case_b, 3);
	flat_jmp32 (&fixture, case_b + 5, dispatcher_addr);
	fixture.data[exit_addr - fixture.base] = 0xc3;
	fixture.data[dispatcher_addr - fixture.base] = 0xff;
	fixture.data[dispatcher_addr - fixture.base + 1] = 0xe0;

	RAnal *anal = flat_anal_new (&fixture);
	RAnalFunction *fcn = r_anal_create_function (anal, "flat_register", entry_addr, 0, NULL);
	mu_assert_notnull (fcn, "create function");
	flat_add_block (anal, fcn, entry_addr, 10);
	flat_add_block (anal, fcn, case_a, 10);
	flat_add_block (anal, fcn, case_b, 10);
	flat_add_block (anal, fcn, exit_addr, 1);
	RAnalBlock *dispatcher = flat_add_block (anal, fcn, dispatcher_addr, 2);

	RAnalBlock *entry = flat_fcn_block (fcn, entry_addr);
	RAnalBlock *block_a = flat_fcn_block (fcn, case_a);
	RAnalBlock *block_b = flat_fcn_block (fcn, case_b);
	mu_assert_notnull (entry, "entry block");
	mu_assert_notnull (block_a, "case A block");
	mu_assert_notnull (block_b, "case B block");
	entry->jump = dispatcher_addr;
	block_a->jump = dispatcher_addr;
	block_b->jump = dispatcher_addr;
	mu_assert_true (flat_dispatcher_switch (dispatcher, exit_addr), "create dispatcher switch");
	dispatcher->switch_op->reg = "eax";
	r_anal_block_add_switch_case (dispatcher, dispatcher_addr, 1, case_a);
	r_anal_block_add_switch_case (dispatcher, dispatcher_addr, 2, case_b);
	r_anal_block_add_switch_case (dispatcher, dispatcher_addr, 3, exit_addr);

	RAnalDeobfFlattenOptions options;
	r_anal_deobf_flatten_options_init (&options);
	options.min_cases = 3;
	RAnalDeobfFlattenStats stats = { 0 };
	mu_assert_true (r_anal_deobf_flatten (anal, fcn, &options, &stats), "recover register flattening");
	mu_assert_true (stats.recognized, "dispatcher recognized");
	mu_assert_true (stats.changed, "CFG changed");
	mu_assert_streq (stats.state_var, "reg eax", "state register");
	mu_assert_eq (stats.blocks_before, 5, "blocks before");
	mu_assert_eq (stats.blocks_after, 4, "blocks after");
	mu_assert_eq (stats.edges, 3, "rewired edges");
	mu_assert_eq (stats.removed, 1, "removed dispatcher");
	mu_assert_false (r_anal_function_contains (fcn, dispatcher_addr), "dispatcher removed from function");
	mu_assert_eq (flat_fcn_block (fcn, entry_addr)->jump, case_a, "entry successor");
	mu_assert_eq (flat_fcn_block (fcn, case_a)->jump, case_b, "case A successor");
	mu_assert_eq (flat_fcn_block (fcn, case_b)->jump, exit_addr, "case B successor");

	r_anal_deobf_flatten_stats_fini (&stats);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_deobf_flatten_memory_state(void) {
	FlatFixture fixture = {
		.base = 0x1100,
		.size = sizeof (fixture.data),
	};
	const ut64 entry_addr = 0x1100;
	const ut64 case_a = 0x1110;
	const ut64 case_b = 0x1120;
	const ut64 exit_addr = 0x1130;
	const ut64 dispatcher_addr = 0x1140;

	flat_mov_state_imm (&fixture, entry_addr, 1);
	flat_jmp32 (&fixture, entry_addr + 7, dispatcher_addr);
	flat_mov_state_imm (&fixture, case_a, 2);
	flat_jmp32 (&fixture, case_a + 7, dispatcher_addr);
	flat_mov_state_imm (&fixture, case_b, 4);
	flat_jmp32 (&fixture, case_b + 7, dispatcher_addr);
	fixture.data[exit_addr - fixture.base] = 0xc3;
	ut8 *dispatch = fixture.data + (dispatcher_addr - fixture.base);
	dispatch[0] = 0x8b;
	dispatch[1] = 0x45;
	dispatch[2] = 0xfc;
	dispatch[3] = 0xff;
	dispatch[4] = 0xe0;

	RAnal *anal = flat_anal_new (&fixture);
	RAnalFunction *fcn = r_anal_create_function (anal, "flat_memory", entry_addr, 0, NULL);
	mu_assert_notnull (fcn, "create function");
	flat_add_block (anal, fcn, entry_addr, 12);
	flat_add_block (anal, fcn, case_a, 12);
	flat_add_block (anal, fcn, case_b, 12);
	flat_add_block (anal, fcn, exit_addr, 1);
	RAnalBlock *dispatcher = flat_add_block (anal, fcn, dispatcher_addr, 5);

	RAnalBlock *entry = flat_fcn_block (fcn, entry_addr);
	RAnalBlock *block_a = flat_fcn_block (fcn, case_a);
	RAnalBlock *block_b = flat_fcn_block (fcn, case_b);
	mu_assert_notnull (entry, "entry block");
	mu_assert_notnull (block_a, "case A block");
	mu_assert_notnull (block_b, "case B block");
	entry->jump = dispatcher_addr;
	block_a->jump = dispatcher_addr;
	block_b->jump = dispatcher_addr;
	mu_assert_true (flat_dispatcher_switch (dispatcher, exit_addr), "create dispatcher switch");
	r_anal_block_add_switch_case (dispatcher, dispatcher_addr, 1, case_a);
	r_anal_block_add_switch_case (dispatcher, dispatcher_addr, 2, case_b);
	r_anal_block_add_switch_case (dispatcher, dispatcher_addr, 4, exit_addr);

	RAnalDeobfFlattenOptions options;
	r_anal_deobf_flatten_options_init (&options);
	options.min_cases = 3;
	RAnalDeobfFlattenStats stats = { 0 };
	mu_assert_true (r_anal_deobf_flatten (anal, fcn, &options, &stats), "recover memory flattening");
	mu_assert_true (stats.recognized, "dispatcher recognized");
	mu_assert_true (stats.changed, "CFG changed");
	mu_assert_streq (stats.state_var, "[ebp-4]", "state memory slot");
	mu_assert_eq (stats.blocks_before, 5, "blocks before");
	mu_assert_eq (stats.blocks_after, 4, "blocks after");
	mu_assert_eq (stats.edges, 3, "rewired edges");
	mu_assert_eq (stats.removed, 1, "removed dispatcher");
	mu_assert_false (r_anal_function_contains (fcn, dispatcher_addr), "dispatcher removed from function");
	mu_assert_eq (flat_fcn_block (fcn, entry_addr)->jump, case_a, "entry successor");
	mu_assert_eq (flat_fcn_block (fcn, case_a)->jump, case_b, "case A successor");
	mu_assert_eq (flat_fcn_block (fcn, case_b)->jump, exit_addr, "case B successor");

	r_anal_deobf_flatten_stats_fini (&stats);
	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_anal_deobf_flatten_register_state);
	mu_run_test (test_anal_deobf_flatten_memory_state);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
