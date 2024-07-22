use crate::uw;

/// Register context from which to capture a backtrace.
#[derive(Copy, Clone, Debug)]
pub struct Context {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

impl Context {
    pub(crate) unsafe fn apply(&self, cursor: *mut uw::unw_cursor_t) {
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RAX as i32, self.rax as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RCX as i32, self.rcx as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RDX as i32, self.rdx as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RBX as i32, self.rbx as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RSP as i32, self.rsp as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RBP as i32, self.rbp as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RSI as i32, self.rsi as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RDI as i32, self.rdi as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_R8 as i32, self.r8 as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_R9 as i32, self.r9 as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_R10 as i32, self.r10 as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_R11 as i32, self.r11 as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_R12 as i32, self.r12 as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_R13 as i32, self.r13 as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_R14 as i32, self.r14 as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_R15 as i32, self.r15 as usize);
        uw::unw_set_reg(cursor, uw::UNW_X86_64_RIP as i32, self.rip as usize);
    }

    pub(crate) fn ip(&self) -> usize {
        self.rip as usize
    }
}
