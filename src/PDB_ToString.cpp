#include "PDB_ToString.h"

namespace PDB
{
	const char* ToString(PDB::DBI::StreamHeader::Version value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::VC41: return "VC41";
			case T::V50: return "V50";
			case T::V60: return "V60";
			case T::V70: return "V70";
			case T::V110: return "V110";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::DBI::SectionContribution::Version value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::Ver60: return "Ver60";
			case T::V2: return "V2";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::SymbolRecordKind value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::S_END: return "S_END";
			case T::S_FRAMEPROC: return "S_FRAMEPROC";
			case T::S_OBJNAME: return "S_OBJNAME";
			case T::S_THUNK32: return "S_THUNK32";
			case T::S_BLOCK32: return "S_BLOCK32";
			case T::S_LABEL32: return "S_LABEL32";
			case T::S_CONSTANT: return "S_CONSTANT";
			case T::S_LDATA32: return "S_LDATA32";
			case T::S_GDATA32: return "S_GDATA32";
			case T::S_PUB32: return "S_PUB32";
			case T::S_LPROC32: return "S_LPROC32";
			case T::S_GPROC32: return "S_GPROC32";
			case T::S_REGREL32: return "S_REGREL32";
			case T::S_LTHREAD32: return "S_LTHREAD32";
			case T::S_GTHREAD32: return "S_GTHREAD32";
			case T::S_PROCREF: return "S_PROCREF";
			case T::S_LPROCREF: return "S_LPROCREF";
			case T::S_TRAMPOLINE: return "S_TRAMPOLINE";
			case T::S_SEPCODE: return "S_SEPCODE";
			case T::S_SECTION: return "S_SECTION";
			case T::S_COFFGROUP: return "S_COFFGROUP";
			case T::S_CALLSITEINFO: return "S_CALLSITEINFO";
			case T::S_FRAMECOOKIE: return "S_FRAMECOOKIE";
			case T::S_COMPILE3: return "S_COMPILE3";
			case T::S_ENVBLOCK: return "S_ENVBLOCK";
			case T::S_LOCAL: return "S_LOCAL";
			case T::S_DEFRANGE_REGISTER: return "S_DEFRANGE_REGISTER";
			case T::S_DEFRANGE_FRAMEPOINTER_REL: return "S_DEFRANGE_FRAMEPOINTER_REL";
			case T::S_DEFRANGE_SUBFIELD_REGISTER: return "S_DEFRANGE_SUBFIELD_REGISTER";
			case T::S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: return "S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE";
			case T::S_DEFRANGE_REGISTER_REL: return "S_DEFRANGE_REGISTER_REL";
			case T::S_LPROC32_ID: return "S_LPROC32_ID";
			case T::S_GPROC32_ID: return "S_GPROC32_ID";
			case T::S_BUILDINFO: return "S_BUILDINFO";
			case T::S_INLINESITE: return "S_INLINESITE";
			case T::S_INLINESITE_END: return "S_INLINESITE_END";
			case T::S_PROC_ID_END: return "S_PROC_ID_END";
			case T::S_FILESTATIC: return "S_FILESTATIC";
			case T::S_LPROC32_DPC: return "S_LPROC32_DPC";
			case T::S_LPROC32_DPC_ID: return "S_LPROC32_DPC_ID";
			case T::S_CALLEES: return "S_CALLEES";
			case T::S_CALLERS: return "S_CALLERS";
			case T::S_INLINESITE2: return "S_INLINESITE2";
			case T::S_HEAPALLOCSITE: return "S_HEAPALLOCSITE";
			case T::S_INLINEES: return "S_INLINEES";
			case T::S_UDT: return "S_UDT";
			case T::S_UDT_ST: return "S_UDT_ST";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::ThunkOrdinal value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::NoType: return "NoType";
			case T::ThisAdjustor: return "ThisAdjustor";
			case T::VirtualCall: return "VirtualCall";
			case T::PCode: return "PCode";
			case T::DelayLoad: return "DelayLoad";
			case T::TrampolineIncremental: return "TrampolineIncremental";
			case T::TrampolineBranchIsland: return "TrampolineBranchIsland";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::TrampolineType value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::Incremental: return "Incremental";
			case T::BranchIsland: return "BranchIsland";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::CookieType value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::COPY: return "COPY";
			case T::XOR_SP: return "XOR_SP";
			case T::XOR_BP: return "XOR_BP";
			case T::XOR_R13: return "XOR_R13";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::Register value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::RAX: return "RAX";
			case T::RBX: return "RBX";
			case T::RCX: return "RCX";
			case T::RDX: return "RDX";
			case T::RSI: return "RSI";
			case T::RDI: return "RDI";
			case T::RBP: return "RBP";
			case T::RSP: return "RSP";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::ProcedureFlags value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::None: return "None";
			case T::NoFPO: return "NoFPO";
			case T::InterruptReturn: return "InterruptReturn";
			case T::FarReturn: return "FarReturn";
			case T::NoReturn: return "NoReturn";
			case T::Unreachable: return "Unreachable";
			case T::CustomCallingConvention: return "CustomCallingConvention";
			case T::NoInline: return "NoInline";
			case T::OptimizedDebugInformation: return "OptimizedDebugInformation";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::PublicSymbolFlags value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::None: return "None";
			case T::Code: return "Code";
			case T::Function: return "Function";
			case T::ManagedCode: return "ManagedCode";
			case T::ManagedILCode: return "ManagedILCode";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::CompileSymbolFlags value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::None: return "None";
			case T::SourceLanguageMask: return "SourceLanguageMask";
			case T::EC: return "EC";
			case T::NoDebugInfo: return "NoDebugInfo";
			case T::LTCG: return "LTCG";
			case T::NoDataAlign: return "NoDataAlign";
			case T::ManagedCodeOrDataPresent: return "ManagedCodeOrDataPresent";
			case T::SecurityChecks: return "SecurityChecks";
			case T::HotPatch: return "HotPatch ";
			case T::CVTCIL: return "CVTCIL";
			case T::MSILModule: return "MSILModule";
			case T::SDL: return "SDL";
			case T::PGO: return "PGO";
			case T::Exp: return "Exp";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::CPUType value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::Intel8080: return "Intel8080";
			case T::Intel8086: return "Intel8086";
			case T::Intel80286: return "Intel80286";
			case T::Intel80386: return "Intel80386";
			case T::Intel80486: return "Intel80486";
			case T::Pentium: return "Pentium";
			case T::PentiumII: return "PentiumII";
			case T::PentiumIII: return "PentiumIII";
			case T::MIPS: return "MIPS";
			case T::MIPS16: return "MIPS16";
			case T::MIPS32: return "MIPS32";
			case T::MIPS64: return "MIPS64";
			case T::MIPSI: return "MIPSI";
			case T::MIPSII: return "MIPSII";
			case T::MIPSIII: return "MIPSIII";
			case T::MIPSIV: return "MIPSIV";
			case T::MIPSV: return "MIPSV";
			case T::M68000: return "M68000";
			case T::M68010: return "M68010";
			case T::M68020: return "M68020";
			case T::M68030: return "M68030";
			case T::M68040: return "M68040";
			case T::Alpha: return "Alpha";
			case T::Alpha21164: return "Alpha21164";
			case T::Alpha21164A: return "Alpha21164A";
			case T::Alpha21264: return "Alpha21264";
			case T::Alpha21364: return "Alpha21364";
			case T::PPC601: return "PPC601";
			case T::PPC603: return "PPC603";
			case T::PPC604: return "PPC604";
			case T::PPC620: return "PPC620";
			case T::PPCFP: return "PPCFP";
			case T::PPCBE: return "PPCBE";
			case T::SH3: return "SH3";
			case T::SH3E: return "SH3E";
			case T::SH3DSP: return "SH3DSP";
			case T::SH4: return "SH4";
			case T::SHMedia: return "SHMedia";
			case T::ARM3: return "ARM3";
			case T::ARM4: return "ARM4";
			case T::ARM4T: return "ARM4T";
			case T::ARM5: return "ARM5";
			case T::ARM5T: return "ARM5T";
			case T::ARM6: return "ARM6";
			case T::ARM_XMAC: return "ARM_XMAC";
			case T::ARM_WMMX: return "ARM_WMMX";
			case T::ARM7: return "ARM7";
			case T::Omni: return "Omni";
			case T::IA64: return "IA64";
			case T::IA64_2: return "IA64_2";
			case T::CEE: return "CEE";
			case T::AM33: return "AM33";
			case T::M32R: return "M32R";
			case T::TriCore: return "TriCore";
			case T::X64: return "X64";
			case T::EBC: return "EBC";
			case T::Thumb: return "Thumb";
			case T::ARMNT: return "ARMNT";
			case T::ARM64: return "ARM64";
			case T::HybridX86ARM64: return "HybridX86ARM64";
			case T::ARM64EC: return "ARM64EC";
			case T::ARM64X: return "ARM64X";
			case T::D3D11_Shader: return "D3D11_Shader";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::DebugSubsectionKind value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::S_IGNORE: return "S_IGNORE";
			case T::S_SYMBOLS: return "S_SYMBOLS";
			case T::S_LINES: return "S_LINES";
			case T::S_STRINGTABLE: return "S_STRINGTABLE";
			case T::S_FILECHECKSUMS: return "S_FILECHECKSUMS";
			case T::S_FRAMEDATA: return "S_FRAMEDATA";
			case T::S_INLINEELINES: return "S_INLINEELINES";
			case T::S_CROSSSCOPEIMPORTS: return "S_CROSSSCOPEIMPORTS";
			case T::S_CROSSSCOPEEXPORTS: return "S_CROSSSCOPEEXPORTS";
			case T::S_IL_LINES: return "S_IL_LINES";
			case T::S_FUNC_MDTOKEN_MAP: return "S_FUNC_MDTOKEN_MAP";
			case T::S_TYPE_MDTOKEN_MAP: return "S_TYPE_MDTOKEN_MAP";
			case T::S_MERGED_ASSEMBLYINPUT: return "S_MERGED_ASSEMBLYINPUT";
			case T::S_COFF_SYMBOL_RVA: return "S_COFF_SYMBOL_RVA";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::ChecksumKind value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::None: return "None";
			case T::MD5: return "MD5";
			case T::SHA1: return "SHA1";
			case T::SHA256: return "SHA256";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::DBI::InlineeSourceLineKind value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::Signature: return "Signature";
			case T::SignatureEx: return "SignatureEx";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::ErrorCode value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::Success: return "Success";
			case T::InvalidSuperBlock: return "InvalidSuperBlock";
			case T::InvalidFreeBlockMap: return "InvalidFreeBlockMap";
			case T::InvalidStream: return "InvalidStream";
			case T::InvalidSignature: return "InvalidSignature";
			case T::InvalidStreamIndex: return "InvalidStreamIndex";
			case T::UnknownVersion: return "UnknownVersion";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::IPI::StreamHeader::Version value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::V40: return "V40";
			case T::V41: return "V41";
			case T::V50: return "V50";
			case T::V70: return "V70";
			case T::V80: return "V80";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::IPI::TypeRecordKind value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::LF_FUNC_ID: return "LF_FUNC_ID";
			case T::LF_MFUNC_ID: return "LF_MFUNC_ID";
			case T::LF_BUILDINFO: return "LF_BUILDINFO";
			case T::LF_SUBSTR_LIST: return "LF_SUBSTR_LIST";
			case T::LF_STRING_ID: return "LF_STRING_ID";
			case T::LF_UDT_SRC_LINE: return "LF_UDT_SRC_LINE";
			case T::LF_UDT_MOD_SRC_LINE: return "LF_UDT_MOD_SRC_LINE";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::IPI::BuildInfoType value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::CurrentDirectory: return "CurrentDirectory";
			case T::BuildTool: return "BuildTool";
			case T::SourceFile: return "SourceFile";
			case T::TypeServerPDB: return "TypeServerPDB";
			case T::CommandLine: return "CommandLine";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::TPI::StreamHeader::Version value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::V40: return "V40";
			case T::V41: return "V41";
			case T::V50: return "V50";
			case T::V70: return "V70";
			case T::V80: return "V80";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::TPI::TypeRecordKind value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::LF_POINTER: return "LF_POINTER";
			case T::LF_MODIFIER: return "LF_MODIFIER";
			case T::LF_PROCEDURE: return "LF_PROCEDURE";
			case T::LF_MFUNCTION: return "LF_MFUNCTION";
			case T::LF_LABEL: return "LF_LABEL";
			case T::LF_ARGLIST: return "LF_ARGLIST";
			case T::LF_FIELDLIST: return "LF_FIELDLIST";
			case T::LF_VTSHAPE: return "LF_VTSHAPE";
			case T::LF_BITFIELD: return "LF_BITFIELD";
			case T::LF_METHODLIST: return "LF_METHODLIST";
			case T::LF_ENDPRECOMP: return "LF_ENDPRECOMP";
			case T::LF_BCLASS: return "LF_BCLASS";
			case T::LF_VBCLASS: return "LF_VBCLASS";
			case T::LF_IVBCLASS: return "LF_IVBCLASS";
			case T::LF_FRIENDFCN_ST: return "LF_FRIENDFCN_ST";
			case T::LF_INDEX: return "LF_INDEX";
			case T::LF_MEMBER_ST: return "LF_MEMBER_ST";
			case T::LF_STMEMBER_ST: return "LF_STMEMBER_ST";
			case T::LF_METHOD_ST: return "LF_METHOD_ST";
			case T::LF_NESTTYPE_ST: return "LF_NESTTYPE_ST";
			case T::LF_VFUNCTAB: return "LF_VFUNCTAB";
			case T::LF_FRIENDCLS: return "LF_FRIENDCLS";
			case T::LF_ONEMETHOD_ST: return "LF_ONEMETHOD_ST";
			case T::LF_VFUNCOFF: return "LF_VFUNCOFF";
			case T::LF_NESTTYPEEX_ST: return "LF_NESTTYPEEX_ST";
			case T::LF_MEMBERMODIFY_ST: return "LF_MEMBERMODIFY_ST";
			case T::LF_MANAGED_ST: return "LF_MANAGED_ST";
			case T::LF_SMAX: return "LF_SMAX";
			case T::LF_TYPESERVER: return "LF_TYPESERVER";
			case T::LF_ENUMERATE: return "LF_ENUMERATE";
			case T::LF_ARRAY: return "LF_ARRAY";
			case T::LF_CLASS: return "LF_CLASS";
			case T::LF_STRUCTURE: return "LF_STRUCTURE";
			case T::LF_UNION: return "LF_UNION";
			case T::LF_ENUM: return "LF_ENUM";
			case T::LF_DIMARRAY: return "LF_DIMARRAY";
			case T::LF_PRECOMP: return "LF_PRECOMP";
			case T::LF_ALIAS: return "LF_ALIAS";
			case T::LF_DEFARG: return "LF_DEFARG";
			case T::LF_FRIENDFCN: return "LF_FRIENDFCN";
			case T::LF_MEMBER: return "LF_MEMBER";
			case T::LF_STMEMBER: return "LF_STMEMBER";
			case T::LF_METHOD: return "LF_METHOD";
			case T::LF_NESTTYPE: return "LF_NESTTYPE";
			case T::LF_ONEMETHOD: return "LF_ONEMETHOD";
			case T::LF_NESTTYPEEX: return "LF_NESTTYPEEX";
			case T::LF_MEMBERMODIFY: return "LF_MEMBERMODIFY";
			case T::LF_MANAGED: return "LF_MANAGED";
			case T::LF_TYPESERVER2: return "LF_TYPESERVER2";
			case T::LF_CHAR: return "LF_CHAR";
			case T::LF_SHORT: return "LF_SHORT";
			case T::LF_USHORT: return "LF_USHORT";
			case T::LF_LONG: return "LF_LONG";
			case T::LF_ULONG: return "LF_ULONG";
			case T::LF_REAL32: return "LF_REAL32";
			case T::LF_REAL64: return "LF_REAL64";
			case T::LF_REAL80: return "LF_REAL80";
			case T::LF_REAL128: return "LF_REAL128";
			case T::LF_QUADWORD: return "LF_QUADWORD";
			case T::LF_UQUADWORD: return "LF_UQUADWORD";
			case T::LF_REAL48: return "LF_REAL48";
			case T::LF_COMPLEX32: return "LF_COMPLEX32";
			case T::LF_COMPLEX64: return "LF_COMPLEX64";
			case T::LF_COMPLEX80: return "LF_COMPLEX80";
			case T::LF_COMPLEX128: return "LF_COMPLEX128";
			case T::LF_VARSTRING: return "LF_VARSTRING";
			case T::LF_OCTWORD: return "LF_OCTWORD";
			case T::LF_UOCTWORD: return "LF_UOCTWORD";
			case T::LF_DECIMAL: return "LF_DECIMAL";
			case T::LF_DATE: return "LF_DATE";
			case T::LF_UTF8STRING: return "LF_UTF8STRING";
			case T::LF_REAL16: return "LF_REAL16";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::TPI::TypeIndexKind value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::T_NOTYPE: return "T_NOTYPE";
			case T::T_ABS: return "T_ABS";
			case T::T_SEGMENT: return "T_SEGMENT";
			case T::T_VOID: return "T_VOID";
			case T::T_HRESULT: return "T_HRESULT";
			case T::T_32PHRESULT: return "T_32PHRESULT";
			case T::T_64PHRESULT: return "T_64PHRESULT";
			case T::T_PVOID: return "T_PVOID";
			case T::T_PFVOID: return "T_PFVOID";
			case T::T_PHVOID: return "T_PHVOID";
			case T::T_32PVOID: return "T_32PVOID";
			case T::T_32PFVOID: return "T_32PFVOID";
			case T::T_64PVOID: return "T_64PVOID";
			case T::T_CURRENCY: return "T_CURRENCY";
			case T::T_NBASICSTR: return "T_NBASICSTR";
			case T::T_FBASICSTR: return "T_FBASICSTR";
			case T::T_NOTTRANS: return "T_NOTTRANS";
			case T::T_BIT: return "T_BIT";
			case T::T_PASCHAR: return "T_PASCHAR";
			case T::T_BOOL32FF: return "T_BOOL32FF";
			case T::T_CHAR: return "T_CHAR";
			case T::T_PCHAR: return "T_PCHAR";
			case T::T_PFCHAR: return "T_PFCHAR";
			case T::T_PHCHAR: return "T_PHCHAR";
			case T::T_32PCHAR: return "T_32PCHAR";
			case T::T_32PFCHAR: return "T_32PFCHAR";
			case T::T_64PCHAR: return "T_64PCHAR";
			case T::T_UCHAR: return "T_UCHAR";
			case T::T_PUCHAR: return "T_PUCHAR";
			case T::T_PFUCHAR: return "T_PFUCHAR";
			case T::T_PHUCHAR: return "T_PHUCHAR";
			case T::T_32PUCHAR: return "T_32PUCHAR";
			case T::T_32PFUCHAR: return "T_32PFUCHAR";
			case T::T_64PUCHAR: return "T_64PUCHAR";
			case T::T_RCHAR: return "T_RCHAR";
			case T::T_PRCHAR: return "T_PRCHAR";
			case T::T_PFRCHAR: return "T_PFRCHAR";
			case T::T_PHRCHAR: return "T_PHRCHAR";
			case T::T_32PRCHAR: return "T_32PRCHAR";
			case T::T_32PFRCHAR: return "T_32PFRCHAR";
			case T::T_64PRCHAR: return "T_64PRCHAR";
			case T::T_WCHAR: return "T_WCHAR";
			case T::T_PWCHAR: return "T_PWCHAR";
			case T::T_PFWCHAR: return "T_PFWCHAR";
			case T::T_PHWCHAR: return "T_PHWCHAR";
			case T::T_32PWCHAR: return "T_32PWCHAR";
			case T::T_32PFWCHAR: return "T_32PFWCHAR";
			case T::T_64PWCHAR: return "T_64PWCHAR";
			case T::T_CHAR8: return "T_CHAR8";
			case T::T_PCHAR8: return "T_PCHAR8";
			case T::T_PFCHAR8: return "T_PFCHAR8";
			case T::T_PHCHAR8: return "T_PHCHAR8";
			case T::T_32PCHAR8: return "T_32PCHAR8";
			case T::T_32PFCHAR8: return "T_32PFCHAR8";
			case T::T_64PCHAR8: return "T_64PCHAR8";
			case T::T_CHAR16: return "T_CHAR16";
			case T::T_PCHAR16: return "T_PCHAR16";
			case T::T_PFCHAR16: return "T_PFCHAR16";
			case T::T_PHCHAR16: return "T_PHCHAR16";
			case T::T_32PCHAR16: return "T_32PCHAR16";
			case T::T_32PFCHAR16: return "T_32PFCHAR16";
			case T::T_64PCHAR16: return "T_64PCHAR16";
			case T::T_CHAR32: return "T_CHAR32";
			case T::T_PCHAR32: return "T_PCHAR32";
			case T::T_PFCHAR32: return "T_PFCHAR32";
			case T::T_PHCHAR32: return "T_PHCHAR32";
			case T::T_32PCHAR32: return "T_32PCHAR32";
			case T::T_32PFCHAR32: return "T_32PFCHAR32";
			case T::T_64PCHAR32: return "T_64PCHAR32";
			case T::T_INT1: return "T_INT1";
			case T::T_PINT1: return "T_PINT1";
			case T::T_PFINT1: return "T_PFINT1";
			case T::T_PHINT1: return "T_PHINT1";
			case T::T_32PINT1: return "T_32PINT1";
			case T::T_32PFINT1: return "T_32PFINT1";
			case T::T_64PINT1: return "T_64PINT1";
			case T::T_UINT1: return "T_UINT1";
			case T::T_PUINT1: return "T_PUINT1";
			case T::T_PFUINT1: return "T_PFUINT1";
			case T::T_PHUINT1: return "T_PHUINT1";
			case T::T_32PUINT1: return "T_32PUINT1";
			case T::T_32PFUINT1: return "T_32PFUINT1";
			case T::T_64PUINT1: return "T_64PUINT1";
			case T::T_SHORT: return "T_SHORT";
			case T::T_PSHORT: return "T_PSHORT";
			case T::T_PFSHORT: return "T_PFSHORT";
			case T::T_PHSHORT: return "T_PHSHORT";
			case T::T_32PSHORT: return "T_32PSHORT";
			case T::T_32PFSHORT: return "T_32PFSHORT";
			case T::T_64PSHORT: return "T_64PSHORT";
			case T::T_USHORT: return "T_USHORT";
			case T::T_PUSHORT: return "T_PUSHORT";
			case T::T_PFUSHORT: return "T_PFUSHORT";
			case T::T_PHUSHORT: return "T_PHUSHORT";
			case T::T_32PUSHORT: return "T_32PUSHORT";
			case T::T_32PFUSHORT: return "T_32PFUSHORT";
			case T::T_64PUSHORT: return "T_64PUSHORT";
			case T::T_INT2: return "T_INT2";
			case T::T_PINT2: return "T_PINT2";
			case T::T_PFINT2: return "T_PFINT2";
			case T::T_PHINT2: return "T_PHINT2";
			case T::T_32PINT2: return "T_32PINT2";
			case T::T_32PFINT2: return "T_32PFINT2";
			case T::T_64PINT2: return "T_64PINT2";
			case T::T_UINT2: return "T_UINT2";
			case T::T_PUINT2: return "T_PUINT2";
			case T::T_PFUINT2: return "T_PFUINT2";
			case T::T_PHUINT2: return "T_PHUINT2";
			case T::T_32PUINT2: return "T_32PUINT2";
			case T::T_32PFUINT2: return "T_32PFUINT2";
			case T::T_64PUINT2: return "T_64PUINT2";
			case T::T_LONG: return "T_LONG";
			case T::T_PLONG: return "T_PLONG";
			case T::T_PFLONG: return "T_PFLONG";
			case T::T_PHLONG: return "T_PHLONG";
			case T::T_32PLONG: return "T_32PLONG";
			case T::T_32PFLONG: return "T_32PFLONG";
			case T::T_64PLONG: return "T_64PLONG";
			case T::T_ULONG: return "T_ULONG";
			case T::T_PULONG: return "T_PULONG";
			case T::T_PFULONG: return "T_PFULONG";
			case T::T_PHULONG: return "T_PHULONG";
			case T::T_32PULONG: return "T_32PULONG";
			case T::T_32PFULONG: return "T_32PFULONG";
			case T::T_64PULONG: return "T_64PULONG";
			case T::T_INT4: return "T_INT4";
			case T::T_PINT4: return "T_PINT4";
			case T::T_PFINT4: return "T_PFINT4";
			case T::T_PHINT4: return "T_PHINT4";
			case T::T_32PINT4: return "T_32PINT4";
			case T::T_32PFINT4: return "T_32PFINT4";
			case T::T_64PINT4: return "T_64PINT4";
			case T::T_UINT4: return "T_UINT4";
			case T::T_PUINT4: return "T_PUINT4";
			case T::T_PFUINT4: return "T_PFUINT4";
			case T::T_PHUINT4: return "T_PHUINT4";
			case T::T_32PUINT4: return "T_32PUINT4";
			case T::T_32PFUINT4: return "T_32PFUINT4";
			case T::T_64PUINT4: return "T_64PUINT4";
			case T::T_QUAD: return "T_QUAD";
			case T::T_PQUAD: return "T_PQUAD";
			case T::T_PFQUAD: return "T_PFQUAD";
			case T::T_PHQUAD: return "T_PHQUAD";
			case T::T_32PQUAD: return "T_32PQUAD";
			case T::T_32PFQUAD: return "T_32PFQUAD";
			case T::T_64PQUAD: return "T_64PQUAD";
			case T::T_UQUAD: return "T_UQUAD";
			case T::T_PUQUAD: return "T_PUQUAD";
			case T::T_PFUQUAD: return "T_PFUQUAD";
			case T::T_PHUQUAD: return "T_PHUQUAD";
			case T::T_32PUQUAD: return "T_32PUQUAD";
			case T::T_32PFUQUAD: return "T_32PFUQUAD";
			case T::T_64PUQUAD: return "T_64PUQUAD";
			case T::T_INT8: return "T_INT8";
			case T::T_PINT8: return "T_PINT8";
			case T::T_PFINT8: return "T_PFINT8";
			case T::T_PHINT8: return "T_PHINT8";
			case T::T_32PINT8: return "T_32PINT8";
			case T::T_32PFINT8: return "T_32PFINT8";
			case T::T_64PINT8: return "T_64PINT8";
			case T::T_UINT8: return "T_UINT8";
			case T::T_PUINT8: return "T_PUINT8";
			case T::T_PFUINT8: return "T_PFUINT8";
			case T::T_PHUINT8: return "T_PHUINT8";
			case T::T_32PUINT8: return "T_32PUINT8";
			case T::T_32PFUINT8: return "T_32PFUINT8";
			case T::T_64PUINT8: return "T_64PUINT8";
			case T::T_OCT: return "T_OCT";
			case T::T_POCT: return "T_POCT";
			case T::T_PFOCT: return "T_PFOCT";
			case T::T_PHOCT: return "T_PHOCT";
			case T::T_32POCT: return "T_32POCT";
			case T::T_32PFOCT: return "T_32PFOCT";
			case T::T_64POCT: return "T_64POCT";
			case T::T_UOCT: return "T_UOCT";
			case T::T_PUOCT: return "T_PUOCT";
			case T::T_PFUOCT: return "T_PFUOCT";
			case T::T_PHUOCT: return "T_PHUOCT";
			case T::T_32PUOCT: return "T_32PUOCT";
			case T::T_32PFUOCT: return "T_32PFUOCT";
			case T::T_64PUOCT: return "T_64PUOCT";
			case T::T_INT16: return "T_INT16";
			case T::T_PINT16: return "T_PINT16";
			case T::T_PFINT16: return "T_PFINT16";
			case T::T_PHINT16: return "T_PHINT16";
			case T::T_32PINT16: return "T_32PINT16";
			case T::T_32PFINT16: return "T_32PFINT16";
			case T::T_64PINT16: return "T_64PINT16";
			case T::T_UINT16: return "T_UINT16";
			case T::T_PUINT16: return "T_PUINT16";
			case T::T_PFUINT16: return "T_PFUINT16";
			case T::T_PHUINT16: return "T_PHUINT16";
			case T::T_32PUINT16: return "T_32PUINT16";
			case T::T_32PFUINT16: return "T_32PFUINT16";
			case T::T_64PUINT16: return "T_64PUINT16";
			case T::T_REAL32: return "T_REAL32";
			case T::T_PREAL32: return "T_PREAL32";
			case T::T_PFREAL32: return "T_PFREAL32";
			case T::T_PHREAL32: return "T_PHREAL32";
			case T::T_32PREAL32: return "T_32PREAL32";
			case T::T_32PFREAL32: return "T_32PFREAL32";
			case T::T_64PREAL32: return "T_64PREAL32";
			case T::T_REAL48: return "T_REAL48";
			case T::T_PREAL48: return "T_PREAL48";
			case T::T_PFREAL48: return "T_PFREAL48";
			case T::T_PHREAL48: return "T_PHREAL48";
			case T::T_32PREAL48: return "T_32PREAL48";
			case T::T_32PFREAL48: return "T_32PFREAL48";
			case T::T_64PREAL48: return "T_64PREAL48";
			case T::T_REAL64: return "T_REAL64";
			case T::T_PREAL64: return "T_PREAL64";
			case T::T_PFREAL64: return "T_PFREAL64";
			case T::T_PHREAL64: return "T_PHREAL64";
			case T::T_32PREAL64: return "T_32PREAL64";
			case T::T_32PFREAL64: return "T_32PFREAL64";
			case T::T_64PREAL64: return "T_64PREAL64";
			case T::T_REAL80: return "T_REAL80";
			case T::T_PREAL80: return "T_PREAL80";
			case T::T_PFREAL80: return "T_PFREAL80";
			case T::T_PHREAL80: return "T_PHREAL80";
			case T::T_32PREAL80: return "T_32PREAL80";
			case T::T_32PFREAL80: return "T_32PFREAL80";
			case T::T_64PREAL80: return "T_64PREAL80";
			case T::T_REAL128: return "T_REAL128";
			case T::T_PREAL128: return "T_PREAL128";
			case T::T_PFREAL128: return "T_PFREAL128";
			case T::T_PHREAL128: return "T_PHREAL128";
			case T::T_32PREAL128: return "T_32PREAL128";
			case T::T_32PFREAL128: return "T_32PFREAL128";
			case T::T_64PREAL128: return "T_64PREAL128";
			case T::T_CPLX32: return "T_CPLX32";
			case T::T_PCPLX32: return "T_PCPLX32";
			case T::T_PFCPLX32: return "T_PFCPLX32";
			case T::T_PHCPLX32: return "T_PHCPLX32";
			case T::T_32PCPLX32: return "T_32PCPLX32";
			case T::T_32PFCPLX32: return "T_32PFCPLX32";
			case T::T_64PCPLX32: return "T_64PCPLX32";
			case T::T_CPLX64: return "T_CPLX64";
			case T::T_PCPLX64: return "T_PCPLX64";
			case T::T_PFCPLX64: return "T_PFCPLX64";
			case T::T_PHCPLX64: return "T_PHCPLX64";
			case T::T_32PCPLX64: return "T_32PCPLX64";
			case T::T_32PFCPLX64: return "T_32PFCPLX64";
			case T::T_64PCPLX64: return "T_64PCPLX64";
			case T::T_CPLX80: return "T_CPLX80";
			case T::T_PCPLX80: return "T_PCPLX80";
			case T::T_PFCPLX80: return "T_PFCPLX80";
			case T::T_PHCPLX80: return "T_PHCPLX80";
			case T::T_32PCPLX80: return "T_32PCPLX80";
			case T::T_32PFCPLX80: return "T_32PFCPLX80";
			case T::T_64PCPLX80: return "T_64PCPLX80";
			case T::T_CPLX128: return "T_CPLX128";
			case T::T_PCPLX128: return "T_PCPLX128";
			case T::T_PFCPLX128: return "T_PFCPLX128";
			case T::T_PHCPLX128: return "T_PHCPLX128";
			case T::T_32PCPLX128: return "T_32PCPLX128";
			case T::T_32PFCPLX128: return "T_32PFCPLX128";
			case T::T_64PCPLX128: return "T_64PCPLX128";
			case T::T_BOOL08: return "T_BOOL08";
			case T::T_PBOOL08: return "T_PBOOL08";
			case T::T_PFBOOL08: return "T_PFBOOL08";
			case T::T_PHBOOL08: return "T_PHBOOL08";
			case T::T_32PBOOL08: return "T_32PBOOL08";
			case T::T_32PFBOOL08: return "T_32PFBOOL08";
			case T::T_64PBOOL08: return "T_64PBOOL08";
			case T::T_BOOL16: return "T_BOOL16";
			case T::T_PBOOL16: return "T_PBOOL16";
			case T::T_PFBOOL16: return "T_PFBOOL16";
			case T::T_PHBOOL16: return "T_PHBOOL16";
			case T::T_32PBOOL16: return "T_32PBOOL16";
			case T::T_32PFBOOL16: return "T_32PFBOOL16";
			case T::T_64PBOOL16: return "T_64PBOOL16";
			case T::T_BOOL32: return "T_BOOL32";
			case T::T_PBOOL32: return "T_PBOOL32";
			case T::T_PFBOOL32: return "T_PFBOOL32";
			case T::T_PHBOOL32: return "T_PHBOOL32";
			case T::T_32PBOOL32: return "T_32PBOOL32";
			case T::T_32PFBOOL32: return "T_32PFBOOL32";
			case T::T_64PBOOL32: return "T_64PBOOL32";
			case T::T_BOOL64: return "T_BOOL64";
			case T::T_PBOOL64: return "T_PBOOL64";
			case T::T_PFBOOL64: return "T_PFBOOL64";
			case T::T_PHBOOL64: return "T_PHBOOL64";
			case T::T_32PBOOL64: return "T_32PBOOL64";
			case T::T_32PFBOOL64: return "T_32PFBOOL64";
			case T::T_64PBOOL64: return "T_64PBOOL64";
			case T::T_NCVPTR: return "T_NCVPTR";
			case T::T_FCVPTR: return "T_FCVPTR";
			case T::T_HCVPTR: return "T_HCVPTR";
			case T::T_32NCVPTR: return "T_32NCVPTR";
			case T::T_32FCVPTR: return "T_32FCVPTR";
			case T::T_64NCVPTR: return "T_64NCVPTR";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::TPI::CallingConvention value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::NEAR_C: return "NEAR_C";
			case T::FAR_C: return "FAR_C";
			case T::NEAR_PASCAL: return "NEAR_PASCAL";
			case T::FAR_PASCAL: return "FAR_PASCAL";
			case T::NEAR_FAST: return "NEAR_FAST";
			case T::FAR_FAST: return "FAR_FAST";
			case T::SKIPPED: return "SKIPPED";
			case T::NEAR_STD: return "NEAR_STD";
			case T::FAR_STD: return "FAR_STD";
			case T::NEAR_SYS: return "NEAR_SYS";
			case T::FAR_SYS: return "FAR_SYS";
			case T::THISCALL: return "THISCALL";
			case T::MIPSCALL: return "MIPSCALL";
			case T::GENERIC: return "GENERIC";
			case T::ALPHACALL: return "ALPHACALL";
			case T::PPCCALL: return "PPCCALL";
			case T::SHCALL: return "SHCALL";
			case T::ARMCALL: return "ARMCALL";
			case T::AM33CALL: return "AM33CALL";
			case T::TRICALL: return "TRICALL";
			case T::SH5CALL: return "SH5CALL";
			case T::M32RCALL: return "M32RCALL";
			case T::CLRCALL: return "CLRCALL";
			case T::INLINE: return "INLINE";
			case T::NEAR_VECTOR: return "NEAR_VECTOR";
			case T::RESERVED: return "RESERVED";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::CodeView::TPI::MethodProperty value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::Vanilla: return "Vanilla";
			case T::Virtual: return "Virtual";
			case T::Static: return "Static";
			case T::Friend: return "Friend";
			case T::Intro: return "Intro";
			case T::PureVirt: return "PureVirt";
			case T::PureIntro: return "PureIntro";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::Header::Version value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::VC2: return "VC2";
			case T::VC4: return "VC4";
			case T::VC41: return "VC41";
			case T::VC50: return "VC50";
			case T::VC98: return "VC98";
			case T::VC70Dep: return "VC70Dep";
			case T::VC70: return "VC70";
			case T::VC80: return "VC80";
			case T::VC110: return "VC110";
			case T::VC140: return "VC140";
		}
		return "UNKNOWN";
	}

	const char* ToString(PDB::FeatureCode value)
	{
		using T = decltype(value);
		switch(value)
		{
			case T::VC110: return "VC110";
			case T::VC140: return "VC140";
			case T::NoTypeMerge: return "NoTypeMerge";
			case T::MinimalDebugInfo: return "MinimalDebugInfo";
		}
		return "UNKNOWN";
	}
}