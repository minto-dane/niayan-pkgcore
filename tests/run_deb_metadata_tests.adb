-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Directories; with Ada.Strings; with Ada.Strings.Fixed; with Ada.Text_IO;
with Interfaces.C;
with MC_Types; use MC_Types;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime;
with MC_SHA256; with MC_Store; with MC_Text;
with Pkg_Deb_Fields; with Pkg_Deb_Metadata; with Pkg_Deb_Semantics;
with Test_Support; use Test_Support;
procedure Run_Deb_Metadata_Tests with SPARK_Mode => Off is
   use type Interfaces.C.unsigned; use type Pkg_Deb_Semantics.Multi_Arch;
   package DF renames Pkg_Deb_Fields; package DM renames Pkg_Deb_Metadata;
   use type DF.Metadata;
   Store : MC_Store.Store; Media : MC_FS.Root; Status : Outcome;
   Parsed : DF.Document; Identity : DF.Metadata; Result : DM.Observation;
   Object : Digest; Now, Deadline : Counter;
   Buffer : Bytes (1 .. 8192); Used : Natural;
   Base : constant String := "Package: fixture" & ASCII.LF & "Version: 1:2.0-1" & ASCII.LF
      & "Architecture: amd64" & ASCII.LF & "Maintainer: Fixture <fixture@example.invalid>" & ASCII.LF
      & "Description: fixture summary" & ASCII.LF & " first line" & ASCII.LF & " ." & ASCII.LF & "  indented" & ASCII.LF;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   function Data (S : String) return Bytes is
      B : Bytes (1 .. S'Length);
   begin for I in S'Range loop B (I - S'First + 1) := Character'Pos (S (I)); end loop; return B; end Data;
   function Text (B : Bytes) return String is
      S : String (1 .. B'Length);
   begin for I in B'Range loop S (I - B'First + 1) := Character'Val (B (I)); end loop; return S; end Text;
   procedure Reject (Raw : Bytes; Label_Text : String) is
   begin
      DF.Parse (Raw, Parsed, Status); Expect (Status /= OK, Label_Text);
      Expect (DF.Field_Count (Parsed) = 0 and then DF.Content_Hash (Parsed) = Zero_Digest, "no partial parsed result");
   end Reject;
   procedure Identity_Reject (Raw : Bytes; Label_Text : String) is
   begin
      DF.Parse (Raw, Parsed, Status); Need ("identity fixture field syntax");
      DF.Check_Identity (Raw, Parsed, Identity, Status);
      Expect (Status /= OK and then Identity = DF.Metadata'(others => <>), Label_Text);
   end Identity_Reject;
   function Replace (Old, New_Value : String) return Bytes is
      At_Byte : constant Natural := Ada.Strings.Fixed.Index (Base, Old);
   begin return Data (Base (1 .. At_Byte - 1) & New_Value & Base (At_Byte + Old'Length .. Base'Last)); end Replace;
   procedure Actual (Filename : String) is
      F : MC_FS.File;
   begin
      MC_FS.Open_Read (Media, Filename, F, Status); Need ("original fixture");
      MC_Store.Import_File (Store, F, MC_Store.Max_Object_Size, Object, Status); Need ("original import"); MC_FS.Close (F);
      DM.Inspect (Store, Object, Deadline, Result, Status); Need ("original native metadata path");
      Expect (Result.Original = Object and then DF.Content_Hash (Result.Fields) = Result.Control, "original/control/index binding");
      Ada.Text_IO.Put_Line ("ORIGINAL " & MC_Hex.Encode (Result.Original));
      Ada.Text_IO.Put_Line ("CONTROL " & MC_Hex.Encode (Result.Control));
      Ada.Text_IO.Put_Line ("PACKAGE " & MC_Text.Image (Result.Identity.Name));
      Ada.Text_IO.Put_Line ("VERSION " & MC_Text.Image (Result.Identity.Version));
      Ada.Text_IO.Put_Line ("ARCHITECTURE " & MC_Text.Image (Result.Identity.Architecture));
      Ada.Text_IO.Put_Line ("SOURCE " & MC_Text.Image (Result.Identity.Source_Name) & " " & MC_Text.Image (Result.Identity.Source_Version));
      Ada.Text_IO.Put_Line ("MULTI " & Pkg_Deb_Semantics.Multi_Arch'Image (Result.Identity.Multi));
      Ada.Text_IO.Put_Line ("ESSENTIAL " & Boolean'Image (Result.Identity.Essential));
      Ada.Text_IO.Put_Line ("PROTECTED " & Boolean'Image (Result.Identity.Protected_Package));
      Ada.Text_IO.Put_Line ("INSTALLED_SIZE " & Boolean'Image (Result.Identity.Has_Installed_Size) & Counter'Image (Result.Identity.Installed_Size_KiB));
      for I in 1 .. DF.Field_Count (Result.Fields) loop Ada.Text_IO.Put_Line ("FIELD " & DF.Field_Name (Result.Fields, I)); end loop;
   end Actual;
begin
   Expect (Ada.Command_Line.Argument_Count in 2 | 3, "fresh CAS and fixtures, optionally actual filename");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      DM.Inspect (Store, (others => 1), Counter'Last, Result, Status);
      Expect (Status = Denied and then Result.Original = Zero_Digest and then DF.Field_Count (Result.Fields) = 0,
         "root metadata reader refused before storage access"); Report; return;
   end if;
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 120_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("fixtures root");
   if Ada.Command_Line.Argument_Count = 3 then
      Actual (Ada.Command_Line.Argument (3));
   else
      declare Raw : constant Bytes := Data (Base & "X_Future!: retain" & ASCII.LF); begin
         DF.Parse (Raw, Parsed, Status); Need ("single binary stanza");
         Expect (DF.Field_Count (Parsed) = 6 and then DF.Has_Field (Parsed, "PACKAGE")
            and then DF.Has_Field (Parsed, "x_future!"), "case-insensitive full printable field-name syntax");
         Expect (DF.Content_Hash (Parsed) = MC_SHA256.Hash (Raw), "complete raw binding");
         DF.Check_Identity (Raw, Parsed, Identity, Status); Need ("mandatory identity fields");
         Expect (MC_Text.Image (Identity.Name) = "fixture" and then MC_Text.Image (Identity.Version) = "1:2.0-1"
            and then MC_Text.Equal (Identity.Source_Name, Identity.Name) and then MC_Text.Equal (Identity.Source_Version, Identity.Version),
            "identity and implicit source identity");
         DF.Read_Value (Raw, Parsed, "description", DF.Multiline, Buffer, Used, Status); Need ("multiline display read");
         Expect (Text (Buffer (1 .. Used)) = "fixture summary" & ASCII.LF & "first line" & ASCII.LF & "." & ASCII.LF & " indented",
            "multiline spacing and blank-line escape retained");
         DF.Read_Value (Raw, Parsed, "description", DF.Simple, Buffer, Used, Status);
         Expect (Status = Invalid_Input and then Used = 0, "simple value cannot hide folding");
         DF.Read_Value (Raw, Parsed, "description", DF.Folded, Buffer, Used, Status); Need ("explicit folded representation");
         Expect (Text (Buffer (1 .. Used)) = "fixture summary first line . indented", "folded whitespace semantics");
         DF.Read_Value (Raw, Parsed, "x_future!", DF.Raw_Field, Buffer, Used, Status); Need ("unknown raw value");
         Expect (Text (Buffer (1 .. Used)) = " retain", "raw field bytes unchanged");
         DF.Read_Value (Raw & Data ("" & ASCII.LF), Parsed, "package", DF.Simple, Buffer, Used, Status);
         Expect (Status = Conflict and then Used = 0, "index rejects different raw control");
         DF.Read_Value (Raw, Parsed, "description", DF.Multiline, Buffer (1 .. 2), Used, Status);
         Expect (Status = Exhausted and then Used = 0 and then Buffer (1 .. 2) = Bytes'(0, 0), "no value truncation or partial output");
      end;
      declare Raw : constant Bytes := Data (Base & "Source: source-fixture (3:4.0-2)" & ASCII.LF & "Multi-Arch: same" & ASCII.LF
         & "Essential: yes" & ASCII.LF & "Protected: no" & ASCII.LF & "Installed-Size: 000123" & ASCII.LF); begin
         DF.Parse (Raw, Parsed, Status); Need ("identity options syntax"); DF.Check_Identity (Raw, Parsed, Identity, Status); Need ("identity options");
         Expect (MC_Text.Image (Identity.Source_Name) = "source-fixture" and then MC_Text.Image (Identity.Source_Version) = "3:4.0-2"
            and then Identity.Multi = Pkg_Deb_Semantics.Same and then Identity.Essential and then not Identity.Protected_Package
            and then Identity.Has_Installed_Size and then Identity.Installed_Size_KiB = 123, "options retain native meanings");
      end;
      declare
         LF_Raw : constant Bytes := Data (ASCII.LF & Base & ASCII.LF);
         Non_One : Bytes (101 .. 100 + LF_Raw'Length);
         CRLF : String (1 .. Base'Length * 2); Count : Natural := 0;
      begin
         Non_One := LF_Raw; DF.Parse (Non_One, Parsed, Status); Need ("non-one buffer bounds and exterior blank lines");
         DF.Check_Identity (Non_One, Parsed, Identity, Status); Need ("identity with offset byte array");
         for C of Base loop
            if C = ASCII.LF then Count := Count + 1; CRLF (Count) := ASCII.CR; end if;
            Count := Count + 1; CRLF (Count) := C;
         end loop;
         DF.Parse (Data (CRLF (1 .. Count)), Parsed, Status); Need ("CRLF framing");
         DF.Check_Identity (Data (CRLF (1 .. Count)), Parsed, Identity, Status); Need ("CRLF identity");
      end;
      Reject (Data (""), "empty control"); Reject (Data (" " & ASCII.HT), "whitespace input");
      Reject (Data (Base & "PACKAGE: other" & ASCII.LF), "case-insensitive duplicate");
      Reject (Data (Base & ASCII.LF & "Other: value"), "multiple stanzas");
      Reject (Data (" orphan" & ASCII.LF & Base), "orphan continuation");
      Reject (Data (Base & "#comment"), "source comment forbidden in binary control");
      Reject (Data (Base & "-Field: value"), "hyphen prefix"); Reject (Data (Base & "Bad Field: value"), "field whitespace");
      Reject (Data (Base & "Empty:  " & ASCII.LF), "empty binary field");
      Reject (Data (Base & "Empty:" & ASCII.LF & "  " & ASCII.LF), "whitespace-only value");
      Reject (Data (Base & "Field: value" & ASCII.CR), "bare CR");
      Reject (Data (Base & "Field: " & ASCII.NUL), "NUL control");
      Reject (Data (Base & "Field: ") & Bytes'(16#C0#, 16#80#), "overlong UTF-8");
      Reject (Data (Base & "Field: ") & Bytes'(16#ED#, 16#A0#, 16#80#), "UTF-8 surrogate");
      Reject (Data (Base & "Field: ") & Bytes'(16#F4#, 16#90#, 16#80#, 16#80#), "out-of-range Unicode");
      Reject (Data (Base & "Field: ") & Bytes'(16#E6#, 16#97#), "truncated UTF-8");
      declare Raw : constant Bytes := Data (Base & "Unicode: ") & Bytes'(16#E6#, 16#97#, 16#A5#, 16#F0#, 16#9F#, 16#8C#, 16#90#); begin
         DF.Parse (Raw, Parsed, Status); Need ("UTF-8 Japanese and supplementary character");
         DF.Read_Value (Raw, Parsed, "unicode", DF.Simple, Buffer, Used, Status); Need ("UTF-8 readback");
         Expect (Buffer (1 .. Used) = Raw (Raw'Last - 6 .. Raw'Last), "no locale-dependent transcoding");
      end;
      Identity_Reject (Replace ("Package: fixture", "Package: a"), "short package name");
      Identity_Reject (Replace ("Package: fixture", "Other: fixture"), "missing package");
      Identity_Reject (Replace ("Version: 1:2.0-1", "Other: 1:2.0-1"), "missing version");
      Identity_Reject (Replace ("Architecture: amd64", "Other: amd64"), "missing architecture");
      Identity_Reject (Replace ("Maintainer: Fixture <fixture@example.invalid>", "Other: fixture"), "missing maintainer");
      Identity_Reject (Replace ("Description: fixture summary", "Other: fixture summary"), "missing description");
      Identity_Reject (Replace ("Description: fixture summary", "Description:"), "empty description summary");
      Identity_Reject (Replace ("Package: fixture", "Package: Fixture"), "uppercase package name");
      Identity_Reject (Replace ("Version: 1:2.0-1", "Version: 2147483648:1"), "version epoch range");
      Identity_Reject (Replace ("Version: 1:2.0-1", "Version: 1^2"), "foreign version grammar");
      Identity_Reject (Replace ("Architecture: amd64", "Architecture: any"), "binary wildcard architecture");
      Identity_Reject (Replace ("Architecture: amd64", "Architecture: all") & Data ("Multi-Arch: same" & ASCII.LF), "all cannot be same");
      Identity_Reject (Data (Base & "Essential: Yes" & ASCII.LF), "case-sensitive flag value");
      Identity_Reject (Data (Base & "Protected: maybe" & ASCII.LF), "unknown protection value");
      Identity_Reject (Data (Base & "Installed-Size: -1" & ASCII.LF), "negative declared size");
      Identity_Reject (Data (Base & "Installed-Size: 9223372036854775808" & ASCII.LF), "declared size overflow");
      Identity_Reject (Data (Base & "Source: src (bad)" & ASCII.LF), "invalid source version");
      Identity_Reject (Replace ("Package: fixture", "Package: fix" & ASCII.LF & " ture"), "folded identity field");
      declare
         Prefix : constant Bytes := Data (Base & "Long: ");
         Raw : Bytes (1 .. Prefix'Length + DF.Max_Line);
         Last : constant Natural := Prefix'Length + DF.Max_Line - 6;
      begin
         Raw (1 .. Prefix'Length) := Prefix; Raw (Prefix'Length + 1 .. Raw'Last) := (others => Character'Pos ('x'));
         DF.Parse (Raw (1 .. Last), Parsed, Status); Need ("line length boundary");
         Reject (Raw (1 .. Last + 1), "line length ceiling");
      end;
      declare Raw : Bytes (1 .. 100_000); Count : Natural := Base'Length; begin
         Raw (1 .. Count) := Data (Base);
         for I in 6 .. DF.Max_Fields + 1 loop
            declare More : constant Bytes := Data ("X-" & Ada.Strings.Fixed.Trim (Natural'Image (I), Ada.Strings.Both) & ": value" & ASCII.LF); begin
               Raw (Count + 1 .. Count + More'Length) := More; Count := Count + More'Length;
            end;
            if I = DF.Max_Fields then DF.Parse (Raw (1 .. Count), Parsed, Status); Need ("field count boundary");
            elsif I > DF.Max_Fields then Reject (Raw (1 .. Count), "field count ceiling"); end if;
         end loop;
      end;
      Actual ("valid-xz.deb");
      Expect (MC_Text.Image (Result.Identity.Name) = "fixture", "native original path identity");
      DM.Inspect (Store, Object, 0, Result, Status);
      Expect (Status = Stale and then Result.Control = Zero_Digest and then DF.Field_Count (Result.Fields) = 0, "expired complete metadata path");
      Actual ("valid-relations.deb");
      Expect (DF.Has_Field (Result.Fields, "provides"), "full path retains architecture-qualified provides");
      declare F : MC_FS.File; begin
         MC_FS.Open_Read (Media, "valid-control-invalid-relations.deb", F, Status); Need ("invalid relation original");
         MC_Store.Import_File (Store, F, MC_Store.Max_Object_Size, Object, Status); Need ("invalid relation import"); MC_FS.Close (F);
         DM.Inspect (Store, Object, Deadline, Result, Status);
         Expect (Status = Invalid_Input and then Result.Control = Zero_Digest and then DF.Field_Count (Result.Fields) = 0,
            "original path refuses relation syntax without partial identity");
      end;
   end if;
   MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Deb_Metadata_Tests;
