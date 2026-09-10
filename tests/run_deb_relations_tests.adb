-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types;
with MC_Text; with MC_SHA256;
with Pkg_Deb_Fields; with Pkg_Deb_Relations; with Pkg_Deb_Semantics;
with Test_Support; use Test_Support;
procedure Run_Deb_Relations_Tests with SPARK_Mode => Off is
   package DR renames Pkg_Deb_Relations;
   package DS renames Pkg_Deb_Semantics;
   use type DR.Field_Kind; use type DR.Atom; use type DS.Relation;
   Result : DR.Expression; Item : DR.Atom; Status : Outcome;
   Fields : Pkg_Deb_Fields.Document;
   function Data (S : String) return Bytes is
      B : Bytes (1 .. S'Length);
   begin for I in S'Range loop B (I - S'First + 1) := Character'Pos (S (I)); end loop; return B; end Data;
   procedure Good (S : String; Kind : DR.Field_Kind; Atoms, Groups : Natural) is
   begin
      DR.Parse (S, Kind, Result, Status);
      Expect (Status = OK and then DR.Count (Result) = Atoms and then DR.Groups (Result) = Groups
         and then DR.Kind_Of (Result) = Kind, "valid " & DR.Field_Name (Kind));
      Expect (DR.Control_Hash (Result) = Zero_Digest, "text alone does not claim control binding");
   end Good;
   procedure Bad (S : String; Kind : DR.Field_Kind := DR.Depends; Expected : Outcome := Invalid_Input) is
   begin
      DR.Parse (S, Kind, Result, Status);
      Expect (Status = Expected and then DR.Count (Result) = 0 and then DR.Groups (Result) = 0
         and then DR.Control_Hash (Result) = Zero_Digest, "reject malformed/unsupported relationship");
   end Bad;
   procedure Atom_Is (Index, Group : Positive; Name, Architecture, Version : String; Operator : DS.Relation) is
   begin
      DR.Read_Atom (Result, Index, Item, Status);
      Expect (Status = OK and then Item.Group_Number = Group and then MC_Text.Image (Item.Name) = Name
         and then MC_Text.Image (Item.Architecture) = Architecture and then MC_Text.Image (Item.Version) = Version
         and then Item.Operator = Operator, "ordered atom with exact attributes");
   end Atom_Is;
   procedure Read (Raw : Bytes; Kind : DR.Field_Kind) is
   begin
      Pkg_Deb_Fields.Parse (Raw, Fields, Status); Expect (Status = OK, "control fixture syntax");
      DR.Read_Field (Raw, Fields, Kind, Result, Status);
   end Read;
   -- Read-only qualification protocol, not installed as a public command.
   procedure Probe is
      Found : Boolean := False;
   begin
      for Kind in DR.Field_Kind loop
         if Ada.Command_Line.Argument (1) = DR.Field_Name (Kind) then
            Found := True; DR.Parse (Ada.Command_Line.Argument (2), Kind, Result, Status); exit;
         end if;
      end loop;
      if not Found or else Status /= OK then Ada.Command_Line.Set_Exit_Status (1); return; end if;
      for I in 1 .. DR.Count (Result) loop
         DR.Read_Atom (Result, I, Item, Status); Expect (Status = OK, "probe atom");
         Ada.Text_IO.Put_Line (Natural'Image (Item.Group_Number) & "|" & MC_Text.Image (Item.Name)
            & "|" & MC_Text.Image (Item.Architecture) & "|" & DS.Relation'Image (Item.Operator)
            & "|" & MC_Text.Image (Item.Version));
      end loop;
   end Probe;
begin
   if Ada.Command_Line.Argument_Count = 2 then Probe; return; end if;
   Expect (Ada.Command_Line.Argument_Count = 0, "unit or read-only probe arguments");
   Good ("libc6:any (>= 2.41) | alternate:arm64, data (=1:2.0~rc1-3)", DR.Depends, 3, 2);
   Atom_Is (1, 1, "libc6", "any", "2.41", DS.At_Least);
   Atom_Is (2, 1, "alternate", "arm64", "", DS.Any_Version);
   Atom_Is (3, 2, "data", "", "1:2.0~rc1-3", DS.Exactly);
   DR.Read_Atom (Result, 4, Item, Status);
   Expect (Status = Invalid_Input and then Item = DR.Atom'(others => <>), "no partial/out-of-range atom");
   Good (" aa(<<1),bb (<= 2),cc(=3),dd(>=4),ee(>>5) " & ASCII.HT, DR.Depends, 5, 5);
   Atom_Is (1, 1, "aa", "", "1", DS.Less_Than); Atom_Is (2, 2, "bb", "", "2", DS.At_Most);
   Atom_Is (3, 3, "cc", "", "3", DS.Exactly); Atom_Is (4, 4, "dd", "", "4", DS.At_Least);
   Atom_Is (5, 5, "ee", "", "5", DS.Greater_Than);
   for Kind in DR.Field_Kind loop
      Good ("package-a (= 1), package-b (= 2)", Kind, 2, 2);
      if Kind in DR.Depends | DR.Pre_Depends | DR.Recommends | DR.Suggests then
         Good ("aa | bb, cc | dd", Kind, 4, 2);
      else Bad ("aa | bb", Kind); end if;
      if Kind in DR.Built_Using | DR.Static_Built_Using then
         Bad ("aa", Kind); Bad ("aa (>= 1)", Kind); Bad ("aa:any (=1)", Kind);
      else
         Good ("virtual-name:any (= 1), other:arm64", Kind, 2, 2);
         Atom_Is (1, 1, "virtual-name", "any", "1", DS.Exactly);
         Atom_Is (2, 2, "other", "arm64", "", DS.Any_Version);
      end if;
   end loop;
   Bad ("aa (>= 1)", DR.Provides); Bad ("aa (<< 1)", DR.Provides);
   Bad (""); Bad (" " & ASCII.HT); Bad ("aa,"); Bad (",aa"); Bad ("aa||bb"); Bad ("aa, ,bb");
   Bad ("aa|"); Bad ("aa bb"); Bad ("aa | | bb"); Bad ("aa,bb ???");
   Bad ("a"); Bad ("-aa"); Bad ("+aa"); Bad ("AA"); Bad ("aa_bb"); Bad ("aa/bb");
   Bad ("aa :any"); Bad ("aa:"); Bad ("aa: any"); Bad ("aa:ARM64"); Bad ("aa:any:amd64");
   Bad ("aa ()"); Bad ("aa (1)"); Bad ("aa (==1)"); Bad ("aa (!=1)");
   Bad ("aa (> 1)"); Bad ("aa (< 1)"); Bad ("aa (><1)"); Bad ("aa (>=)");
   Bad ("aa (=1 2)"); Bad ("aa (=1"); Bad ("aa (=1))"); Bad ("aa (=1)(=2)");
   Bad ("aa (=not-a-version)"); Bad ("aa (=2147483648:1)"); Bad ("aa (=1^2)");
   Bad ("aa [amd64]"); Bad ("aa <!nocheck>"); Bad ("${misc:Depends}");
   Bad ("aa," & ASCII.LF & " bb"); Bad ("aa" & ASCII.CR); Bad ("aa" & ASCII.VT);
   Bad ("aa" & ASCII.NUL); Bad ("aa" & Character'Val (127)); Bad ("aa" & Character'Val (16#C2#));
   declare
      Shifted : String (7 .. 11) := "aa|bb";
   begin Good (Shifted, DR.Depends, 2, 1); Atom_Is (2, 1, "bb", "", "", DS.Any_Version); end;
   declare
      Many : String (1 .. 3 * DR.Max_Atoms - 1) := (others => ',');
   begin
      for I in 0 .. DR.Max_Atoms - 1 loop Many (I * 3 + 1 .. I * 3 + 2) := "aa"; end loop;
      Good (Many, DR.Depends, DR.Max_Atoms, DR.Max_Atoms);
      Atom_Is (DR.Max_Atoms, DR.Max_Atoms, "aa", "", "", DS.Any_Version);
      Bad (Many & ",aa", Expected => Exhausted);
      for I in Many'Range loop if Many (I) = ',' then Many (I) := '|'; end if; end loop;
      Good (Many, DR.Depends, DR.Max_Atoms, 1); Bad (Many & "|aa", Expected => Exhausted);
   end;
   Good (String'(1 .. MC_Text.Max_Length => 'a'), DR.Depends, 1, 1);
   Bad (String'(1 .. MC_Text.Max_Length + 1 => 'a'), Expected => Exhausted);
   Good ("aa:" & String'(1 .. MC_Text.Max_Length => 'a'), DR.Depends, 1, 1);
   Bad ("aa:" & String'(1 .. MC_Text.Max_Length + 1 => 'a'), Expected => Exhausted);
   Good ("aa (=1" & String'(1 .. 511 => 'a') & ")", DR.Depends, 1, 1);
   Bad ("aa (=1" & String'(1 .. 512 => 'a') & ")");
   Good ("aa:native, aa:native", DR.Depends, 2, 2);
   Atom_Is (2, 2, "aa", "native", "", DS.Any_Version);
   Good ("aa" & String'(1 .. DR.Max_Value - 2 => ' '), DR.Depends, 1, 1);
   Bad ("aa" & String'(1 .. DR.Max_Value - 1 => ' '), Expected => Exhausted);
   declare
      Raw : constant Bytes := Data ("Depends: aa (>= 1) | bb" & ASCII.LF & "Provides: cc:arm64 (=2)" & ASCII.LF);
   begin
      Read (Raw, DR.Depends);
      Expect (Status = OK and then DR.Control_Hash (Result) = MC_SHA256.Hash (Raw), "full control hash bound");
      Atom_Is (2, 1, "bb", "", "", DS.Any_Version);
      DR.Read_Field (Raw, Fields, DR.Built_Using, Result, Status);
      Expect (Status = OK and then DR.Count (Result) = 0 and then DR.Kind_Of (Result) = DR.Built_Using
         and then DR.Control_Hash (Result) = MC_SHA256.Hash (Raw), "authenticated absence in exact document");
      DR.Read_Field (Data ("Different: bytes" & ASCII.LF), Fields, DR.Built_Using, Result, Status);
      Expect (Status /= OK and then DR.Control_Hash (Result) = Zero_Digest, "absence cannot bypass source binding");
      DR.Validate_All (Raw, Fields, Status); Expect (Status = OK, "all eleven fields checked");
   end;
   Read (Data ("Depends: aa," & ASCII.LF & " bb" & ASCII.LF), DR.Depends);
   Expect (Status /= OK and then DR.Count (Result) = 0, "binary folding rejected before normalization");
   Read (Data ("Depends: aa" & ASCII.LF & "Provides: bb (>= 1)" & ASCII.LF), DR.Depends);
   Expect (Status = OK, "isolated field read does not validate unrelated field");
   DR.Validate_All (Data ("Depends: aa" & ASCII.LF & "Provides: bb (>= 1)" & ASCII.LF), Fields, Status);
   Expect (Status = Invalid_Input, "whole relation check rejects invalid provides");
   Report;
end Run_Deb_Relations_Tests;
