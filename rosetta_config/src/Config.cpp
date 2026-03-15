#include "rosetta_config/Config.h"

#include <cstdlib>
#include <cstring>

struct NameBit {
    const char* name;
    int bit;
};

static const NameBit kOpcodeBits[] = {
    {"fldz",     static_cast<int>(OpcodeId::fldz)},
    {"fld1",     static_cast<int>(OpcodeId::fld1)},
    {"fldl2e",   static_cast<int>(OpcodeId::fldl2e)},
    {"fldl2t",   static_cast<int>(OpcodeId::fldl2t)},
    {"fldlg2",   static_cast<int>(OpcodeId::fldlg2)},
    {"fldln2",   static_cast<int>(OpcodeId::fldln2)},
    {"fldpi",    static_cast<int>(OpcodeId::fldpi)},
    {"fld",      static_cast<int>(OpcodeId::fld)},
    {"fild",     static_cast<int>(OpcodeId::fild)},
    {"fadd",     static_cast<int>(OpcodeId::fadd)},
    {"faddp",    static_cast<int>(OpcodeId::faddp)},
    {"fiadd",    static_cast<int>(OpcodeId::fiadd)},
    {"fsub",     static_cast<int>(OpcodeId::fsub)},
    {"fsubr",    static_cast<int>(OpcodeId::fsubr)},
    {"fsubp",    static_cast<int>(OpcodeId::fsubp)},
    {"fsubrp",   static_cast<int>(OpcodeId::fsubrp)},
    {"fdiv",     static_cast<int>(OpcodeId::fdiv)},
    {"fdivr",    static_cast<int>(OpcodeId::fdivr)},
    {"fdivp",    static_cast<int>(OpcodeId::fdivp)},
    {"fdivrp",   static_cast<int>(OpcodeId::fdivrp)},
    {"fmul",     static_cast<int>(OpcodeId::fmul)},
    {"fmulp",    static_cast<int>(OpcodeId::fmulp)},
    {"fst",      static_cast<int>(OpcodeId::fst)},
    {"fst_stack",static_cast<int>(OpcodeId::fst_stack)},
    {"fstp",     static_cast<int>(OpcodeId::fstp)},
    {"fstp_stack",static_cast<int>(OpcodeId::fstp_stack)},
    {"fstsw",    static_cast<int>(OpcodeId::fstsw)},
    {"fcom",     static_cast<int>(OpcodeId::fcom)},
    {"fcomp",    static_cast<int>(OpcodeId::fcomp)},
    {"fcompp",   static_cast<int>(OpcodeId::fcompp)},
    {"fucom",    static_cast<int>(OpcodeId::fucom)},
    {"fucomp",   static_cast<int>(OpcodeId::fucomp)},
    {"fucompp",  static_cast<int>(OpcodeId::fucompp)},
    {"fxch",     static_cast<int>(OpcodeId::fxch)},
    {"fchs",     static_cast<int>(OpcodeId::fchs)},
    {"fabs",     static_cast<int>(OpcodeId::fabs)},
    {"fsqrt",    static_cast<int>(OpcodeId::fsqrt)},
    {"fistp",    static_cast<int>(OpcodeId::fistp)},
    {"fidiv",    static_cast<int>(OpcodeId::fidiv)},
    {"fimul",    static_cast<int>(OpcodeId::fimul)},
    {"fisub",    static_cast<int>(OpcodeId::fisub)},
    {"fidivr",   static_cast<int>(OpcodeId::fidivr)},
    {"frndint",  static_cast<int>(OpcodeId::frndint)},
    {"fcomi",    static_cast<int>(OpcodeId::fcomi)},
    {"fcomip",   static_cast<int>(OpcodeId::fcomip)},
    {"fucomi",   static_cast<int>(OpcodeId::fucomi)},
    {"fucomip",  static_cast<int>(OpcodeId::fucomip)},
    {"ftst",     static_cast<int>(OpcodeId::ftst)},
    {"fist",     static_cast<int>(OpcodeId::fist)},
    {"fisubr",   static_cast<int>(OpcodeId::fisubr)},
    {"fcmovb",   static_cast<int>(OpcodeId::fcmovb)},
    {"fcmovbe",  static_cast<int>(OpcodeId::fcmovbe)},
    {"fcmove",   static_cast<int>(OpcodeId::fcmove)},
    {"fcmovnb",  static_cast<int>(OpcodeId::fcmovnb)},
    {"fcmovnbe", static_cast<int>(OpcodeId::fcmovnbe)},
    {"fcmovne",  static_cast<int>(OpcodeId::fcmovne)},
    {"fcmovu",   static_cast<int>(OpcodeId::fcmovu)},
    {"fcmovnu",  static_cast<int>(OpcodeId::fcmovnu)},
};

static const NameBit kFusionBits[] = {
    {"fld_arithp",      static_cast<int>(FusionId::fld_arithp)},
    {"fld_fstp",        static_cast<int>(FusionId::fld_fstp)},
    {"fld_arith_fstp",  static_cast<int>(FusionId::fld_arith_fstp)},
    {"fld_fcomp_fstsw", static_cast<int>(FusionId::fld_fcomp_fstsw)},
    {"fxch_arithp",     static_cast<int>(FusionId::fxch_arithp)},
    {"fxch_fstp",       static_cast<int>(FusionId::fxch_fstp)},
    {"fcom_fstsw",      static_cast<int>(FusionId::fcom_fstsw)},
    {"fld_fcompp_fstsw",static_cast<int>(FusionId::fld_fcompp_fstsw)},
    {"fld_fld_fucompp", static_cast<int>(FusionId::fld_fld_fucompp)},
    {"fld_fcomp",       static_cast<int>(FusionId::fld_fcomp)},
    {"fld_arith_arithp",static_cast<int>(FusionId::fld_arith_arithp)},
    {"arithp_fstp",     static_cast<int>(FusionId::arithp_fstp)},
    {"fstp_fld",        static_cast<int>(FusionId::fstp_fld)},
};

static void apply_mask_from_env(const char* env_var, uint64_t& mask,
                                const NameBit* table, int table_len) {
    const char* v = std::getenv(env_var);
    if (!v || !*v)
        return;

    char buf[512];
    std::strncpy(buf, v, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char* save = nullptr;
    char* tok = strtok_r(buf, ",", &save);
    while (tok) {
        for (int i = 0; i < table_len; i++) {
            if (std::strcmp(tok, table[i].name) == 0) {
                mask |= 1ULL << table[i].bit;
                break;
            }
        }
        tok = strtok_r(nullptr, ",", &save);
    }
}

RosettaConfig parse_config_from_env() {
    RosettaConfig cfg = {};

    if (const char* v = std::getenv("ROSETTA_X87_DISABLE_CACHE"))
        cfg.disable_x87_cache = (*v == '1') ? 1 : 0;

    if (const char* v = std::getenv("ROSETTA_X87_FAST_ROUND"))
        cfg.fast_round = (*v == '1') ? 1 : 0;

    if (const char* v = std::getenv("ROSETTA_X87_DISABLE_ALL_OPS"))
        if (*v == '1')
            cfg.disabled_ops_mask = ~0ULL;

    if (const char* v = std::getenv("ROSETTA_X87_DISABLE_ALL_FUSIONS"))
        if (*v == '1')
            cfg.disabled_fusions_mask = ~0ULL;

    constexpr int kOpcodeCount = sizeof(kOpcodeBits) / sizeof(kOpcodeBits[0]);
    constexpr int kFusionCount = sizeof(kFusionBits) / sizeof(kFusionBits[0]);

    apply_mask_from_env("ROSETTA_X87_DISABLE_OPS",     cfg.disabled_ops_mask,
                        kOpcodeBits, kOpcodeCount);
    apply_mask_from_env("ROSETTA_X87_DISABLE_FUSIONS", cfg.disabled_fusions_mask,
                        kFusionBits, kFusionCount);

    return cfg;
}
