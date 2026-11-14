# OLLVM control-flow flattening recovery

`aafd` recovers the analysis graph of functions protected with the common
OLLVM control-flow flattening transformation. It changes radare2 analysis
metadata only; it does not patch the input bytes.

## Usage

After the regular analysis:

```sh
aaa
aafd
pdf
agf
```

Use `aafd <addr>` to process the function containing a specific address. The
internal quiet form is `aafdq`; it is used by automatic recovery.

Automatic recovery is disabled by default:

```sh
e anal.ollvm=true
e anal.ollvm.min_cases=3
aaa
```

`anal.ollvm.min_cases` is the minimum number of in-function switch cases
required before a dispatcher candidate is accepted. Raising it reduces false
positives in functions with normal switch statements.

## What is recovered

The pass looks for a dispatcher block that:

- owns an `RAnalSwitchOp` with enough distinct case targets, or is an indirect
  jump with enough backedges;
- receives direct control-flow edges from at least two other blocks;
- uses a state value that is written as a small set of constants before those
  backedges.

It recognizes both a state register and a stack/global state slot loaded from
memory. Constant assignments such as `mov eax, 2` and
`mov dword [rbp - 4], 2` are folded into the corresponding switch case target.
The dispatcher delete/reachability pass then rebuilds predecessor/successor
edges and drops dispatcher blocks that become unreachable.

Each rewritten assignment receives a comment similar to:

```text
; ollvm: state 0x2 -> 0x401020
```

The original instruction bytes and the state assignments remain visible, but
`pdf`, `agf`, and code that consumes `RAnalFunction` block edges see the
recovered CFG.

## Scope and limitations

This pass targets the classic constant-state OLLVM layout where real blocks
write the state variable and jump back to one dispatcher. It does not try to
solve symbolic state expressions, encoded state transitions, opaque predicates,
indirect state through multiple aliases, or VM/interpreter dispatch loops.
An indirect dispatcher without a usable `RAnalSwitchOp` case map is reported
as recognized but is not rewritten.

The analysis is conservative: it requires multiple state assignments and
multiple distinct case targets, and leaves edges untouched when a state value
cannot be mapped unambiguously. It also preserves existing comments.

## False positives

Normal switch-based state machines, coroutine schedulers, bytecode interpreters,
and loops that intentionally return to a central switch can resemble flattened
control flow. The case-count and backedge checks reduce this risk, but they do
not eliminate it. Prefer `aafd <addr>` on a specific suspect function instead of
enabling `anal.ollvm` globally, and use a larger `anal.ollvm.min_cases` for
binaries with many ordinary switches. Re-running function analysis (`af` or
`aaa`) restores the original graph if the result was not useful.
