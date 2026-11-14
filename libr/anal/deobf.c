/* radare - LGPL - Copyright 2026 - pancake */

#include <r_anal.h>
#include <r_util.h>

#define DEOBF_MAX_SELECTORS 32
#define DEOBF_MAX_REG_STATE 64
#define DEOBF_MAX_BLOCK_SIZE (1024 * 1024)

typedef struct {
	char name[64];
	ut64 value;
	bool known;
} DeobfRegState;

typedef struct {
	bool is_mem;
	char *reg;
	char *index;
	char *seg;
	st64 delta;
	int memref;
	int assignments;
} DeobfSelector;

typedef struct {
	ut64 value;
	ut64 op_addr;
	bool found;
} DeobfStateWrite;

typedef bool (*DeobfOpCb)(RAnalOp *op, void *user);

static bool deobf_read_at(RAnal *anal, ut64 addr, ut8 *buf, int len) {
	if (anal->read_at) {
		return anal->read_at (anal, addr, buf, len);
	}
	if (anal->iob.read_at && anal->iob.io) {
		return anal->iob.read_at (anal->iob.io, addr, buf, len) == len;
	}
	return false;
}

static bool deobf_block_ops(RAnal *anal, RAnalBlock *block, DeobfOpCb cb, void *user) {
	if (!block->size || block->size > DEOBF_MAX_BLOCK_SIZE) {
		return false;
	}
	const size_t size = (size_t)block->size;
	ut8 *buf = malloc (size);
	if (!buf) {
		return false;
	}
	if (!deobf_read_at (anal, block->addr, buf, (int)size)) {
		free (buf);
		return false;
	}
	size_t pos = 0;
	bool ok = true;
	while (pos < size) {
		RAnalOp op = { 0 };
		const int len = r_anal_op (anal, &op, block->addr + pos, buf + pos,
			(int)(size - pos), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL);
		if (len < 1 || (size_t)len > size - pos) {
			r_anal_op_fini (&op);
			ok = false;
			break;
		}
		const bool keep_going = cb (&op, user);
		r_anal_op_fini (&op);
		if (!keep_going) {
			ok = false;
			break;
		}
		pos += len;
	}
	free (buf);
	return ok;
}

static bool deobf_block_last_op(RAnal *anal, RAnalBlock *block, RAnalOp *out) {
	RAnalOp last = { 0 };
	bool have_last = false;
	size_t pos = 0;
	const size_t size = (size_t)block->size;
	if (!size || size > DEOBF_MAX_BLOCK_SIZE) {
		return false;
	}
	ut8 *buf = malloc (size);
	if (!buf) {
		return false;
	}
	if (!deobf_read_at (anal, block->addr, buf, (int)size)) {
		free (buf);
		return false;
	}
	while (pos < size) {
		RAnalOp op = { 0 };
		const int len = r_anal_op (anal, &op, block->addr + pos, buf + pos,
			(int)(size - pos), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL);
		if (len < 1 || (size_t)len > size - pos) {
			r_anal_op_fini (&op);
			break;
		}
		r_anal_op_fini (&last);
		last = op;
		have_last = true;
		pos += len;
	}
	free (buf);
	if (!have_last) {
		return false;
	}
	*out = last;
	return true;
}

static void deobf_selector_free(DeobfSelector *selector) {
	if (selector) {
		free (selector->reg);
		free (selector->index);
		free (selector->seg);
		free (selector);
	}
}

static bool deobf_streq_null(const char *a, const char *b) {
	if (!a || !b) {
		return a == b;
	}
	return !r_str_casecmp (a, b);
}

static bool deobf_value_is_mem(const RArchValue *value) {
	return value->memref > 0 || value->type == R_ANAL_VAL_MEM;
}

static bool deobf_value_is_reg(const RArchValue *value) {
	return value->reg && !deobf_value_is_mem (value);
}

static void *deobf_addr_to_ptr(ut64 addr) {
	return (void *)(size_t)(addr + 1);
}

static ut64 deobf_ptr_to_addr(const void *ptr) {
	return ptr? (ut64)(size_t)ptr - 1: UT64_MAX;
}

static bool deobf_selector_same(const DeobfSelector *a, const DeobfSelector *b) {
	if (a->is_mem != b->is_mem) {
		return false;
	}
	if (!a->is_mem) {
		return deobf_streq_null (a->reg, b->reg);
	}
	return deobf_streq_null (a->reg, b->reg)
		&& deobf_streq_null (a->index, b->index)
		&& deobf_streq_null (a->seg, b->seg)
		&& a->delta == b->delta
		&& a->memref == b->memref;
}

static DeobfSelector *deobf_selector_new(void) {
	return R_NEW0 (DeobfSelector);
}

static void deobf_selector_add(RList *selectors, DeobfSelector *candidate) {
	if (!candidate || r_list_length (selectors) >= DEOBF_MAX_SELECTORS) {
		deobf_selector_free (candidate);
		return;
	}
	RListIter *iter;
	DeobfSelector *selector;
	r_list_foreach (selectors, iter, selector) {
		if (deobf_selector_same (selector, candidate)) {
			deobf_selector_free (candidate);
			return;
		}
	}
	r_list_append (selectors, candidate);
}

static void deobf_selector_add_reg(RList *selectors, const char *reg) {
	if (!reg || !*reg) {
		return;
	}
	DeobfSelector *selector = deobf_selector_new ();
	selector->reg = strdup (reg);
	if (!selector->reg) {
		free (selector);
		return;
	}
	deobf_selector_add (selectors, selector);
}

static void deobf_selector_add_mem(RList *selectors, const RArchValue *value) {
	if (!value || !deobf_value_is_mem (value) || value->memref < 1) {
		return;
	}
	DeobfSelector *selector = deobf_selector_new ();
	selector->is_mem = true;
	selector->reg = value->reg? strdup (value->reg): NULL;
	selector->index = value->regdelta? strdup (value->regdelta): NULL;
	selector->seg = value->seg? strdup (value->seg): NULL;
	if ((value->reg && !selector->reg) || (value->regdelta && !selector->index)
		|| (value->seg && !selector->seg)) {
		deobf_selector_free (selector);
		return;
	}
	selector->delta = value->delta;
	selector->memref = value->memref;
	deobf_selector_add (selectors, selector);
}

static bool deobf_selector_matches_mem(const DeobfSelector *selector, const RArchValue *value) {
	return deobf_value_is_mem (value)
		&& value->memref == selector->memref
		&& value->delta == selector->delta
		&& deobf_streq_null (value->reg, selector->reg)
		&& deobf_streq_null (value->regdelta, selector->index)
		&& deobf_streq_null (value->seg, selector->seg);
}

static bool deobf_selector_matches_reg(const DeobfSelector *selector, const char *reg) {
	return !selector->is_mem && reg && !r_str_casecmp (selector->reg, reg);
}

static char *deobf_selector_tostring(const DeobfSelector *selector) {
	if (!selector) {
		return NULL;
	}
	if (!selector->is_mem) {
		return r_str_newf ("reg %s", selector->reg);
	}
	RStrBuf *sb = r_strbuf_new ("[");
	if (selector->reg) {
		r_strbuf_append (sb, selector->reg);
	}
	if (selector->index) {
		r_strbuf_append (sb, "+");
		r_strbuf_append (sb, selector->index);
	}
	if (selector->delta) {
		r_strbuf_appendf (sb, "%+" PFMT64d, selector->delta);
	} else if (!selector->reg && !selector->index) {
		r_strbuf_append (sb, "0");
	}
	r_strbuf_append (sb, "]");
	return r_strbuf_drain (sb);
}

static void deobf_reg_set(DeobfRegState *regs, int *count, const char *name, ut64 value, bool known) {
	if (!name || !*name) {
		return;
	}
	int i;
	for (i = 0; i < *count; i++) {
		if (!r_str_casecmp (regs[i].name, name)) {
			regs[i].value = value;
			regs[i].known = known;
			return;
		}
	}
	if (*count >= DEOBF_MAX_REG_STATE) {
		return;
	}
	r_str_ncpy (regs[*count].name, name, sizeof (regs[*count].name));
	regs[*count].value = value;
	regs[*count].known = known;
	(*count)++;
}

static bool deobf_reg_get(DeobfRegState *regs, int count, const char *name, ut64 *value) {
	if (!name) {
		return false;
	}
	int i;
	for (i = 0; i < count; i++) {
		if (!r_str_casecmp (regs[i].name, name)) {
			if (regs[i].known && value) {
				*value = regs[i].value;
			}
			return regs[i].known;
		}
	}
	return false;
}

static bool deobf_value_const(RAnalOp *op, DeobfRegState *regs, int reg_count, ut64 *value) {
	RArchValue *src0 = RVecRArchValue_length (&op->srcs) > 0
		? RVecRArchValue_at (&op->srcs, 0): NULL;
	RArchValue *src1 = RVecRArchValue_length (&op->srcs) > 1
		? RVecRArchValue_at (&op->srcs, 1): NULL;
	if (src0 && (src0->type == R_ANAL_VAL_IMM
		|| (!src0->reg && src0->memref == 0 && op->val != UT64_MAX))) {
		*value = (ut64)src0->imm;
		return true;
	}
	if (src0 && deobf_value_is_reg (src0) && deobf_reg_get (regs, reg_count, src0->reg, value)) {
		return true;
	}
	const ut32 type = op->type & R_ANAL_OP_TYPE_MASK;
	if ((type == R_ANAL_OP_TYPE_XOR || type == R_ANAL_OP_TYPE_SUB)
		&& src0 && src1 && deobf_value_is_reg (src0) && deobf_value_is_reg (src1)
		&& src0->reg && src1->reg && !r_str_casecmp (src0->reg, src1->reg)) {
		*value = 0;
		return true;
	}
	return false;
}

typedef struct {
	DeobfSelector *selectors;
	int selectors_count;
	DeobfRegState regs[DEOBF_MAX_REG_STATE];
	int regs_count;
	bool has[DEOBF_MAX_SELECTORS];
	ut64 values[DEOBF_MAX_SELECTORS];
	ut64 op_addrs[DEOBF_MAX_SELECTORS];
} DeobfExtractCtx;

static bool deobf_extract_op(RAnalOp *op, void *user) {
	DeobfExtractCtx *ctx = user;
	ut64 value = 0;
	const bool have_const = deobf_value_const (op, ctx->regs, ctx->regs_count, &value);
	const ut32 type = op->type & R_ANAL_OP_TYPE_MASK;
	const bool move_like = type == R_ANAL_OP_TYPE_MOV || type == R_ANAL_OP_TYPE_STORE;
	RArchValue *dst;
	R_VEC_FOREACH (&op->dsts, dst) {
		if (deobf_value_is_reg (dst)) {
			if (move_like && have_const) {
				deobf_reg_set (ctx->regs, &ctx->regs_count, dst->reg, value, true);
			} else {
				deobf_reg_set (ctx->regs, &ctx->regs_count, dst->reg, 0, false);
			}
			int i;
			for (i = 0; i < ctx->selectors_count; i++) {
				DeobfSelector *selector = &ctx->selectors[i];
				if (deobf_selector_matches_reg (selector, dst->reg)) {
					ctx->has[i] = move_like && have_const;
					ctx->values[i] = value;
					ctx->op_addrs[i] = op->addr;
				}
			}
		} else if (deobf_value_is_mem (dst) && move_like) {
			int i;
			for (i = 0; i < ctx->selectors_count; i++) {
				DeobfSelector *selector = &ctx->selectors[i];
				if (selector->is_mem && deobf_selector_matches_mem (selector, dst)) {
					ctx->has[i] = have_const;
					ctx->values[i] = value;
					ctx->op_addrs[i] = op->addr;
				}
			}
		}
	}
	return true;
}

static bool deobf_extract_block(RAnal *anal, RAnalBlock *block, DeobfExtractCtx *ctx) {
	ctx->regs_count = 0;
	return deobf_block_ops (anal, block, deobf_extract_op, ctx);
}

static bool deobf_fcn_has_block(RAnalFunction *fcn, ut64 addr) {
	RAnalBlock *block = r_anal_get_block_at (fcn->anal, addr);
	return block && r_list_contains (block->fcns, fcn);
}

static void deobf_add_predecessor(HtUP *predecessors, ut64 addr) {
	if (addr == UT64_MAX) {
		return;
	}
	const size_t count = (size_t)ht_up_find (predecessors, addr, NULL);
	ht_up_update (predecessors, addr, (void *)(count + 1));
}

static HtUP *deobf_count_predecessors(RAnalFunction *fcn) {
	HtUP *predecessors = ht_up_new0 ();
	if (!predecessors) {
		return NULL;
	}
	RAnalBlock **iter;
	RAnalBlock *block;
	R_VEC_FOREACH (&fcn->bbs, iter) {
		block = *iter;
		deobf_add_predecessor (predecessors, block->jump);
		deobf_add_predecessor (predecessors, block->fail);
		if (block->switch_op && block->switch_op->cases) {
			RListIter *it;
			RAnalCaseOp *caseop;
			r_list_foreach (block->switch_op->cases, it, caseop) {
				deobf_add_predecessor (predecessors, caseop->jump);
			}
		}
	}
	return predecessors;
}

static bool deobf_is_indirect_jump(RAnal *anal, RAnalBlock *block) {
	RAnalOp op = { 0 };
	const bool have_op = deobf_block_last_op (anal, block, &op);
	const bool indirect = have_op && (op.type & 0xffff) == R_ANAL_OP_TYPE_UJMP;
	if (have_op) {
		r_anal_op_fini (&op);
	}
	return indirect;
}

static RAnalBlock *deobf_find_dispatcher(RAnal *anal, RAnalFunction *fcn, int min_cases,
		int *cases, int *backedges, bool *indirect) {
	RAnalBlock *best = NULL;
	int best_score = -1;
	int best_cases = 0;
	int best_backedges = 0;
	bool best_indirect = false;
	HtUP *predecessors = deobf_count_predecessors (fcn);
	if (!predecessors) {
		return NULL;
	}
	RAnalBlock **iter;
	RAnalBlock *block;
	R_VEC_FOREACH (&fcn->bbs, iter) {
		block = *iter;
		const int pred_count = (int)(size_t)ht_up_find (predecessors, block->addr, NULL);
		int unique_cases = 0;
		if (block->switch_op && block->switch_op->cases
			&& r_list_length (block->switch_op->cases) >= (size_t)min_cases) {
			HtUP *targets = ht_up_new0 ();
			if (!targets) {
				continue;
			}
			RListIter *it;
			RAnalCaseOp *caseop;
			r_list_foreach (block->switch_op->cases, it, caseop) {
				if (caseop->jump != block->addr && deobf_fcn_has_block (fcn, caseop->jump)
					&& !ht_up_find (targets, caseop->jump, NULL)) {
					ht_up_insert (targets, caseop->jump, (void *)(size_t)1);
					unique_cases++;
				}
			}
			ht_up_free (targets);
			if (unique_cases >= min_cases && pred_count >= 2) {
				const int score = unique_cases * 16 + pred_count;
				if (score > best_score) {
					best = block;
					best_score = score;
					best_cases = unique_cases;
					best_backedges = pred_count;
					best_indirect = false;
				}
			}
		}
		if (pred_count >= min_cases && deobf_is_indirect_jump (anal, block)) {
			const int score = pred_count;
			if (score > best_score) {
				best = block;
				best_score = score;
				best_cases = 0;
				best_backedges = pred_count;
				best_indirect = true;
			}
		}
	}
	ht_up_free (predecessors);
	if (cases) {
		*cases = best_cases;
	}
	if (backedges) {
		*backedges = best_backedges;
	}
	if (indirect) {
		*indirect = best_indirect;
	}
	return best;
}

typedef struct {
	RList *selectors;
} DeobfSelectorCtx;

static bool deobf_collect_selectors_op(RAnalOp *op, void *user) {
	DeobfSelectorCtx *ctx = user;
	if (op->reg) {
		deobf_selector_add_reg (ctx->selectors, op->reg);
	}
	if (op->ireg) {
		deobf_selector_add_reg (ctx->selectors, op->ireg);
	}
	RArchValue *value;
	R_VEC_FOREACH (&op->dsts, value) {
		if (deobf_value_is_mem (value)) {
			deobf_selector_add_mem (ctx->selectors, value);
		} else if (deobf_value_is_reg (value)) {
			deobf_selector_add_reg (ctx->selectors, value->reg);
		}
	}
	R_VEC_FOREACH (&op->srcs, value) {
		if (deobf_value_is_mem (value)) {
			deobf_selector_add_mem (ctx->selectors, value);
		}
	}
	const ut32 type = op->type & R_ANAL_OP_TYPE_MASK;
	if (type == R_ANAL_OP_TYPE_CMP) {
		R_VEC_FOREACH (&op->srcs, value) {
			if (deobf_value_is_reg (value)) {
				deobf_selector_add_reg (ctx->selectors, value->reg);
			}
		}
	}
	return true;
}

static bool deobf_block_edges_dispatcher(RAnalBlock *block, RAnalBlock *dispatcher) {
	return block != dispatcher
		&& (block->jump == dispatcher->addr || block->fail == dispatcher->addr);
}

static void deobf_score_selectors(RAnal *anal, RAnalFunction *fcn, RAnalBlock *dispatcher,
		RList *selector_list) {
	const int selectors_count = (int)r_list_length (selector_list);
	if (!selectors_count) {
		return;
	}
	DeobfSelector *selectors = R_NEWS0 (DeobfSelector, selectors_count);
	if (!selectors) {
		return;
	}
	RListIter *list_iter;
	DeobfSelector *selector;
	int index = 0;
	r_list_foreach (selector_list, list_iter, selector) {
		selectors[index++] = *selector;
	}
	RAnalBlock **iter;
	RAnalBlock *block;
	DeobfExtractCtx ctx = {
		.selectors = selectors,
		.selectors_count = selectors_count,
	};
	R_VEC_FOREACH (&fcn->bbs, iter) {
		block = *iter;
		if (!deobf_block_edges_dispatcher (block, dispatcher)) {
			continue;
		}
		memset (ctx.regs, 0, sizeof (ctx.regs));
		ctx.regs_count = 0;
		memset (ctx.has, 0, sizeof (ctx.has));
		memset (ctx.values, 0, sizeof (ctx.values));
		memset (ctx.op_addrs, 0, sizeof (ctx.op_addrs));
		deobf_block_ops (anal, block, deobf_extract_op, &ctx);
		int i;
		for (i = 0; i < selectors_count; i++) {
			if (ctx.has[i]) {
				selectors[i].assignments++;
			}
		}
	}
	index = 0;
	r_list_foreach (selector_list, list_iter, selector) {
		selector->assignments = selectors[index++].assignments;
	}
	free (selectors);
}

static DeobfSelector *deobf_best_selector(RList *selectors) {
	DeobfSelector *best = NULL;
	RListIter *iter;
	DeobfSelector *selector;
	r_list_foreach (selectors, iter, selector) {
		if (selector->assignments < 2) {
			continue;
		}
		if (!best || selector->assignments > best->assignments
			|| (selector->assignments == best->assignments && selector->is_mem && !best->is_mem)) {
			best = selector;
		}
	}
	return best;
}

static bool deobf_extract_state_write(RAnal *anal, RAnalBlock *block, DeobfSelector *selector,
		DeobfStateWrite *write) {
	DeobfExtractCtx ctx = {
		.selectors = selector,
		.selectors_count = 1,
	};
	memset (write, 0, sizeof (*write));
	deobf_extract_block (anal, block, &ctx);
	if (!ctx.has[0]) {
		return false;
	}
	write->found = true;
	write->value = ctx.values[0];
	write->op_addr = ctx.op_addrs[0];
	return true;
}

typedef struct {
	RAnalBlock *block;
	ut64 value;
	ut64 target;
	ut64 op_addr;
	bool replace_jump;
} DeobfMappedEdge;

static bool deobf_build_case_map(RAnalFunction *fcn, RAnalBlock *dispatcher, HtUP *case_map) {
	if (!dispatcher->switch_op || !dispatcher->switch_op->cases) {
		return false;
	}
	int count = 0;
	RListIter *iter;
	RAnalCaseOp *caseop;
	r_list_foreach (dispatcher->switch_op->cases, iter, caseop) {
		if (caseop->jump == dispatcher->addr || !deobf_fcn_has_block (fcn, caseop->jump)) {
			continue;
		}
		if (!ht_up_find (case_map, caseop->value, NULL)) {
			ht_up_insert (case_map, caseop->value, deobf_addr_to_ptr (caseop->jump));
			count++;
		}
	}
	return count >= 2;
}

static RList *deobf_build_edges(RAnal *anal, RAnalFunction *fcn, RAnalBlock *dispatcher,
		DeobfSelector *selector, HtUP *case_map, int *mapped_count) {
	RList *edges = r_list_newf (free);
	HtUP *targets = ht_up_new0 ();
	if (!edges || !targets) {
		r_list_free (edges);
		ht_up_free (targets);
		return NULL;
	}
	RAnalBlock **iter;
	RAnalBlock *block;
	R_VEC_FOREACH (&fcn->bbs, iter) {
		block = *iter;
		if (!deobf_block_edges_dispatcher (block, dispatcher)) {
			continue;
		}
		if (block->jump == dispatcher->addr && block->fail == dispatcher->addr) {
			continue;
		}
		if (block->switch_op && block->switch_op->cases
			&& !r_list_empty (block->switch_op->cases)) {
			continue;
		}
		DeobfStateWrite write;
		if (!deobf_extract_state_write (anal, block, selector, &write)) {
			continue;
		}
		ut64 target = deobf_ptr_to_addr (ht_up_find (case_map, write.value, NULL));
		if (target == UT64_MAX || target == dispatcher->addr || !deobf_fcn_has_block (fcn, target)) {
			continue;
		}
		DeobfMappedEdge *edge = R_NEW0 (DeobfMappedEdge);
		edge->block = block;
		edge->value = write.value;
		edge->target = target;
		edge->op_addr = write.op_addr;
		edge->replace_jump = block->jump == dispatcher->addr;
		r_list_append (edges, edge);
		ht_up_insert (targets, target, (void *)(size_t)1);
	}
	const int unique_targets = targets->count;
	ht_up_free (targets);
	if (mapped_count) {
		*mapped_count = unique_targets;
	}
	return edges;
}

static void deobf_set_comment(RAnal *anal, ut64 addr, const char *text) {
	if (!text || r_meta_get_string (anal, R_META_TYPE_COMMENT, addr)) {
		return;
	}
	r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, text);
}

static int deobf_remove_unreachable(RAnalFunction *fcn) {
	RAnalBlock *entry = r_anal_get_block_at (fcn->anal, fcn->addr);
	if (!entry || !r_list_contains (entry->fcns, fcn)) {
		return 0;
	}
	HtUP *function_blocks = ht_up_new0 ();
	HtUP *visited = ht_up_new0 ();
	RList *work = r_list_new ();
	RList *remove = r_list_new ();
	if (!function_blocks || !visited || !work || !remove) {
		ht_up_free (function_blocks);
		ht_up_free (visited);
		r_list_free (work);
		r_list_free (remove);
		return 0;
	}
	RAnalBlock **iter;
	RAnalBlock *block;
	R_VEC_FOREACH (&fcn->bbs, iter) {
		block = *iter;
		ht_up_insert (function_blocks, block->addr, block);
	}
	r_list_append (work, entry);
	ht_up_insert (visited, entry->addr, (void *)(size_t)1);
	while (!r_list_empty (work)) {
		block = r_list_pop_head (work);
		if (block->jump != UT64_MAX) {
			RAnalBlock *next = ht_up_find (function_blocks, block->jump, NULL);
			if (next && !ht_up_find (visited, next->addr, NULL)) {
				ht_up_insert (visited, next->addr, (void *)(size_t)1);
				r_list_append (work, next);
			}
		}
		if (block->fail != UT64_MAX) {
			RAnalBlock *next = ht_up_find (function_blocks, block->fail, NULL);
			if (next && !ht_up_find (visited, next->addr, NULL)) {
				ht_up_insert (visited, next->addr, (void *)(size_t)1);
				r_list_append (work, next);
			}
		}
		if (block->switch_op && block->switch_op->cases) {
			RListIter *it;
			RAnalCaseOp *caseop;
			r_list_foreach (block->switch_op->cases, it, caseop) {
				RAnalBlock *next = ht_up_find (function_blocks, caseop->jump, NULL);
				if (next && !ht_up_find (visited, next->addr, NULL)) {
					ht_up_insert (visited, next->addr, (void *)(size_t)1);
					r_list_append (work, next);
				}
			}
		}
		if (block->switch_op && block->switch_op->def_val != UT64_MAX
			&& block->switch_op->def_val != block->addr) {
			RAnalBlock *next = ht_up_find (function_blocks,
				block->switch_op->def_val, NULL);
			if (next && !ht_up_find (visited, next->addr, NULL)) {
				ht_up_insert (visited, next->addr, (void *)(size_t)1);
				r_list_append (work, next);
			}
		}
	}
	R_VEC_FOREACH (&fcn->bbs, iter) {
		block = *iter;
		if (!ht_up_find (visited, block->addr, NULL)) {
			r_list_append (remove, block);
		}
	}
	int removed = 0;
	RListIter *it;
	r_list_foreach (remove, it, block) {
		r_anal_function_remove_block (fcn, block);
		removed++;
	}
	r_list_free (remove);
	r_list_free (work);
	ht_up_free (visited);
	ht_up_free (function_blocks);
	return removed;
}

R_API void r_anal_deobf_flatten_options_init(RAnalDeobfFlattenOptions *options) {
	R_RETURN_IF_FAIL (options);
	options->min_cases = 3;
}

R_API void r_anal_deobf_flatten_stats_fini(RAnalDeobfFlattenStats *stats) {
	R_RETURN_IF_FAIL (stats);
	R_FREE (stats->state_var);
}

R_API bool r_anal_deobf_flatten(RAnal *anal, RAnalFunction *fcn,
		const RAnalDeobfFlattenOptions *options, RAnalDeobfFlattenStats *stats) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && stats, false);
	RAnalDeobfFlattenOptions defaults;
	if (!options) {
		r_anal_deobf_flatten_options_init (&defaults);
		options = &defaults;
	}
	memset (stats, 0, sizeof (*stats));
	stats->blocks_before = (int)RVecAnalBlockPtr_length (&fcn->bbs);
	const int min_cases = options->min_cases > 1? options->min_cases: 2;
	int cases = 0;
	int backedges = 0;
	bool indirect = false;
	RAnalBlock *dispatcher = deobf_find_dispatcher (anal, fcn, min_cases,
		&cases, &backedges, &indirect);
	if (!dispatcher) {
		stats->blocks_after = stats->blocks_before;
		return false;
	}
	stats->recognized = true;
	stats->dispatcher = dispatcher->addr;
	stats->cases = cases;
	stats->backedges = backedges;
	stats->indirect = indirect;
	if (indirect || !dispatcher->switch_op) {
		stats->blocks_after = stats->blocks_before;
		return true;
	}

	RList *selectors = r_list_newf ((RListFree)deobf_selector_free);
	if (!selectors) {
		stats->blocks_after = stats->blocks_before;
		return true;
	}
	if (dispatcher->switch_op->reg) {
		deobf_selector_add_reg (selectors, dispatcher->switch_op->reg);
	}
	DeobfSelectorCtx selector_ctx = { .selectors = selectors };
	deobf_block_ops (anal, dispatcher, deobf_collect_selectors_op, &selector_ctx);
	deobf_score_selectors (anal, fcn, dispatcher, selectors);
	DeobfSelector *selector = deobf_best_selector (selectors);
	if (!selector) {
		r_list_free (selectors);
		stats->blocks_after = stats->blocks_before;
		return true;
	}
	stats->state_var = deobf_selector_tostring (selector);

	HtUP *case_map = ht_up_new0 ();
	if (!case_map || !deobf_build_case_map (fcn, dispatcher, case_map)) {
		ht_up_free (case_map);
		r_list_free (selectors);
		stats->blocks_after = stats->blocks_before;
		return true;
	}
	int unique_targets = 0;
	RList *edges = deobf_build_edges (anal, fcn, dispatcher, selector, case_map, &unique_targets);
	ht_up_free (case_map);
	if (!edges || r_list_length (edges) < 2 || unique_targets < 2) {
		r_list_free (edges);
		r_list_free (selectors);
		stats->blocks_after = stats->blocks_before;
		return true;
	}

	RListIter *iter;
	DeobfMappedEdge *edge;
	r_list_foreach (edges, iter, edge) {
		if (edge->replace_jump) {
			edge->block->jump = edge->target;
		} else {
			edge->block->fail = edge->target;
		}
		stats->rewired++;
		stats->edges++;
		char *comment = r_str_newf ("ollvm: state 0x%" PFMT64x " -> 0x%" PFMT64x,
			edge->value, edge->target);
		deobf_set_comment (anal, edge->op_addr, comment);
		free (comment);
	}
	char *dispatcher_comment = r_str_newf ("ollvm: dispatcher for %s", stats->state_var);
	deobf_set_comment (anal, dispatcher->addr, dispatcher_comment);
	free (dispatcher_comment);
	stats->state_blocks = (int)r_list_length (edges);
	stats->changed = stats->rewired > 0;
	if (stats->changed) {
		stats->removed = deobf_remove_unreachable (fcn);
		stats->blocks_after = (int)RVecAnalBlockPtr_length (&fcn->bbs);
		fcn->ninstr = r_anal_function_instrcount (fcn);
		r_anal_function_bump_dirty_epoch (fcn);
	} else {
		stats->blocks_after = stats->blocks_before;
	}
	r_list_free (edges);
	r_list_free (selectors);
	return true;
}
