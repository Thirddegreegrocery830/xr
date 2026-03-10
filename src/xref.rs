/// A resolved cross-reference between two addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xref {
    /// Address of the instruction that generates this reference.
    pub from: u64,
    /// Target address being referenced.
    pub to: u64,
    /// What kind of reference this is.
    pub kind: XrefKind,
    /// How confident we are in this xref's correctness.
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XrefKind {
    /// Direct call instruction (BL, CALL, etc.)
    Call,
    /// Direct unconditional branch/jump
    Jump,
    /// Direct conditional branch
    CondJump,
    /// Data read reference (LDR, MOV from data section, etc.)
    DataRead,
    /// Data write reference (STR, MOV to data section, etc.)
    DataWrite,
    /// Pointer-sized value in a data section pointing into code/data
    DataPointer,
    /// Indirect call — target not statically resolved at this level
    IndirectCall,
    /// Indirect jump — target not statically resolved at this level
    IndirectJump,
}

/// Confidence level — which analysis level produced this xref.
/// Higher = more expensive analysis, more accurate result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Confidence {
    /// Byte-scan: pointer-sized value in data section that lands in a mapped segment.
    /// Many false positives, especially for non-pointer data.
    ByteScan = 0,
    /// Linear disasm: direct branch/call with an immediate target.
    /// No flow analysis. Misses ADRP+ADD/LDR pairs on ARM64.
    LinearImmediate = 1,
    /// ADRP+completing-instruction pairing (ARM64) or RIP-relative (x86-64).
    /// Sliding window, no CFG needed. Covers ~85-90% of real refs.
    PairResolved = 2,
    /// Local constant propagation within a linear region.
    /// Tracks register state forward, resolves simple indirect targets.
    LocalProp = 3,
    /// Full CFG + dataflow for the containing function.
    /// Most accurate short of interprocedural analysis.
    FunctionFlow = 4,
}

impl Confidence {
    pub fn name(self) -> &'static str {
        match self {
            Self::ByteScan => "byte-scan",
            Self::LinearImmediate => "linear-immediate",
            Self::PairResolved => "pair-resolved",
            Self::LocalProp => "local-prop",
            Self::FunctionFlow => "function-flow",
        }
    }
}

impl XrefKind {
    /// Short ASCII label used in text output and JSON serialisation.
    /// Indirect variants collapse to their direct counterpart category.
    pub fn name(self) -> &'static str {
        match self {
            Self::Call | Self::IndirectCall => "call",
            Self::Jump | Self::CondJump | Self::IndirectJump => "jump",
            Self::DataRead => "data_read",
            Self::DataWrite => "data_write",
            Self::DataPointer => "data_ptr",
        }
    }

    pub fn is_code_ref(self) -> bool {
        matches!(
            self,
            XrefKind::Call
                | XrefKind::Jump
                | XrefKind::CondJump
                | XrefKind::IndirectCall
                | XrefKind::IndirectJump
        )
    }

    pub fn is_data_ref(self) -> bool {
        matches!(
            self,
            XrefKind::DataRead | XrefKind::DataWrite | XrefKind::DataPointer
        )
    }
}
