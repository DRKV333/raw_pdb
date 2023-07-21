#pragma once

#include "PDB_DBITypes.h"
#include "PDB_ErrorCodes.h"
#include "PDB_IPITypes.h"
#include "PDB_TPITypes.h"
#include "PDB_Types.h"

namespace PDB
{
	const char* ToString(PDB::DBI::StreamHeader::Version value);

	const char* ToString(PDB::DBI::SectionContribution::Version value);

	const char* ToString(PDB::CodeView::DBI::SymbolRecordKind value);

	const char* ToString(PDB::CodeView::DBI::ThunkOrdinal value);

	const char* ToString(PDB::CodeView::DBI::TrampolineType value);

	const char* ToString(PDB::CodeView::DBI::CookieType value);

	const char* ToString(PDB::CodeView::DBI::Register value);

	const char* ToString(PDB::CodeView::DBI::ProcedureFlags value);

	const char* ToString(PDB::CodeView::DBI::PublicSymbolFlags value);

	const char* ToString(PDB::CodeView::DBI::CompileSymbolFlags value);

	const char* ToString(PDB::CodeView::DBI::CPUType value);

	const char* ToString(PDB::CodeView::DBI::DebugSubsectionKind value);

	const char* ToString(PDB::CodeView::DBI::ChecksumKind value);

	const char* ToString(PDB::CodeView::DBI::InlineeSourceLineKind value);

	const char* ToString(PDB::ErrorCode value);

	const char* ToString(PDB::IPI::StreamHeader::Version value);

	const char* ToString(PDB::CodeView::IPI::TypeRecordKind value);

	const char* ToString(PDB::CodeView::IPI::BuildInfoType value);

	const char* ToString(PDB::TPI::StreamHeader::Version value);

	const char* ToString(PDB::CodeView::TPI::TypeRecordKind value);

	const char* ToString(PDB::CodeView::TPI::TypeIndexKind value);

	const char* ToString(PDB::CodeView::TPI::CallingConvention value);

	const char* ToString(PDB::CodeView::TPI::MethodProperty value);

	const char* ToString(PDB::Header::Version value);

	const char* ToString(PDB::FeatureCode value);
}