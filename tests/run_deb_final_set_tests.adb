-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Directories; with Ada.Strings.Fixed; with Ada.Text_IO;
with Interfaces.C;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store; with MC_Text;
with MC_Types; use MC_Types;
with Pkg_Deb_Final_Set; with Pkg_Deb_Payload; with Pkg_Deb_Relations;
with Pkg_Payload_Index; with Pkg_Selected_Catalog; with Test_Support; use Test_Support;
procedure Run_Deb_Final_Set_Tests with SPARK_Mode => Off is
   package F renames Pkg_Deb_Final_Set; package C renames Pkg_Selected_Catalog;
   package P renames Pkg_Deb_Payload; package X renames Pkg_Payload_Index;
   use type Interfaces.C.unsigned; use type F.Finding_Kind;
   Store : MC_Store.Store; Media : MC_FS.Root; Status : Outcome; Now, Deadline : Counter;
   Value, Empty : C.Catalog; Payload : X.Index; Source : P.Inventory;
   Result, Saved, Successful : F.Verification; Issue : F.Finding;
   Enabled, Reordered : F.Architecture_List (1 .. 3);
   Selected : C.Selection (1 .. 16); Original, Before : Digest;
   Input : Ada.Text_IO.File_Type; Line : String (1 .. 32768); Last, Position, Cases : Natural := 0;
   procedure Need (Name : String) is
   begin Expect (Status = OK, Name & Outcome'Image (Status)); end Need;
   function Next return String is
      First : Natural;
   begin
      while Position <= Last and then Line (Position) = ' ' loop Position := Position + 1; end loop;
      First := Position;
      while Position <= Last and then Line (Position) /= ' ' loop Position := Position + 1; end loop;
      return Line (First .. Position - 1);
   end Next;
   procedure Import (Name : String) is
      File : MC_FS.File;
   begin
      MC_FS.Open_Read (Media, Name, File, Status); Need ("fixture open");
      MC_Store.Import_File (Store, File, MC_Store.Max_Object_Size, Original, Status); Need ("fixture CAS import"); MC_FS.Close (File);
   exception when others => MC_FS.Close (File); raise;
   end Import;
   procedure No_Receipt is
   begin
      Expect (not F.Passed (Result) and then F.Fingerprint (Result) = Zero_Digest
         and then F.Catalog_Hash (Result) = Zero_Digest and then F.Architecture_Hash (Result) = Zero_Digest,
         "failure cannot retain a successful receipt");
   end No_Receipt;
begin
   Expect (Ada.Command_Line.Argument_Count = 2, "fresh CAS and endpoint fixture directory");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      F.Check (Value, "amd64", Enabled, 0, Result, Status); Expect (Status = Denied, "root check refused before input access");
      No_Receipt; Expect (F.Diagnostic (Result).Kind = F.Not_Checked, "root is not a checked endpoint"); Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("fixture root");
   Ada.Text_IO.Open (Input, Ada.Text_IO.In_File, Ada.Command_Line.Argument (2) & "/cases.txt");
   while not Ada.Text_IO.End_Of_File (Input) loop
      Ada.Text_IO.Get_Line (Input, Line, Last); Expect (Last in 1 .. Line'Last - 1, "bounded complete case line"); Position := 1;
      C.Clear (Value); X.Clear (Payload);
      MC_Clock.Boottime_Milliseconds (Now, Status); Need ("case clock"); Deadline := Now + 60_000;
      declare
         Name : constant String := Next;
         Expected : constant F.Finding_Kind := F.Finding_Kind'Value (Next);
         Native : constant String := Next;
         Arches : constant String := Next;
         First : Positive := Arches'First; Finish : Natural; Count : Natural := 0;
      begin
         for I in Enabled'Range loop
            Finish := Ada.Strings.Fixed.Index (Arches, ",", First);
            if Finish = 0 then Finish := Arches'Last + 1; end if;
            MC_Text.Set (Enabled (I), Arches (First .. Finish - 1), Status); Need ("enabled architecture"); First := Finish + 1;
         end loop;
         while Position <= Last loop
            declare Token : constant String := Next; Separator : constant Natural := Ada.Strings.Fixed.Index (Token, "="); begin
               Expect (Separator > 1 and then Count < Selected'Length, "bounded original/control selection"); Count := Count + 1;
               Import (Token (Token'First .. Separator - 1)); Selected (Count).Original := Original;
               MC_Hex.Decode (Token (Separator + 1 .. Token'Last), Selected (Count).Control, Status); Need ("expected independent control hash");
               P.Stage (Store, Original, Deadline, Source, Status); Need ("payload observation");
               X.Add (Payload, Source, Deadline, Status); Need ("payload source membership"); P.Clear (Source);
               C.Add (Value, Store, Original, Deadline, Status); Need ("native candidate metadata");
            end;
         end loop;
         X.Seal (Payload, Deadline, Status); Need ("payload index");
         C.Seal (Value, Selected (1 .. Count), Payload, Deadline, Status); Need ("exact native candidate"); Before := C.Fingerprint (Value);
         F.Check (Value, Native, Enabled, Deadline, Result, Status); Issue := F.Diagnostic (Result);
         Ada.Text_IO.Put_Line ("CASE " & Name & " " & F.Finding_Kind'Image (Issue.Kind) & " " & Outcome'Image (Status)
            & " " & MC_Hex.Encode (Before) & " " & MC_Hex.Encode (F.Fingerprint (Result))
            & " " & MC_Hex.Encode (F.Architecture_Hash (Result)) & " " & MC_Hex.Encode (F.Catalog_Hash (Result))
            & " " & MC_Hex.Encode (Issue.Original) & " " & MC_Hex.Encode (Issue.Other_Original)
            & " " & Pkg_Deb_Relations.Field_Kind'Image (Issue.Field)
            & Natural'Image (Issue.Group_Number) & Natural'Image (Issue.Atom_Position));
         Expect (Issue.Kind = Expected, Name & ": " & F.Finding_Kind'Image (Expected) & " /= " & F.Finding_Kind'Image (Issue.Kind));
         Expect (C.Fingerprint (Value) = Before, "checking does not mutate the candidate");
         if Expected = F.No_Violation then
            Need ("valid endpoint"); Expect (F.Passed (Result) and then F.Catalog_Hash (Result) = Before
               and then F.Fingerprint (Result) /= Zero_Digest and then F.Architecture_Hash (Result) /= Zero_Digest, "complete endpoint binding");
            Successful := Result;
         else
            Expect (Status = (if Expected = F.Architecture_Not_Enabled then Unsupported else Conflict), "unsatisfied endpoint status"); No_Receipt;
            Expect (Issue.Original /= Zero_Digest, "diagnostic identifies original");
         end if;
         if Cases = 0 then
            Saved := Result; Reordered := (Enabled (3), Enabled (1), Enabled (2));
            F.Check (Value, Native, Reordered, Deadline, Result, Status); Need ("reordered architecture policy");
            Expect (F.Fingerprint (Result) = F.Fingerprint (Saved), "policy order cannot change receipt");
            declare Extra : F.Architecture_List (1 .. 4); begin
               Extra (1 .. 3) := Enabled; MC_Text.Set (Extra (4), "riscv64", Status); Need ("additional policy label");
               F.Check (Value, Native, Extra, Deadline, Result, Status); Need ("broader explicit architecture policy");
               Expect (F.Fingerprint (Result) /= F.Fingerprint (Saved)
                  and then F.Architecture_Hash (Result) /= F.Architecture_Hash (Saved), "policy change changes binding");
            end;
         end if;
         Cases := Cases + 1;
      end;
   end loop;
   Ada.Text_IO.Close (Input); Expect (Cases = 898, "complete checked-in endpoint matrix");
   Result := Successful; F.Check (Value, "amd64", Enabled, 0, Result, Status); Expect (Status = Stale, "expired check"); No_Receipt;
   Result := Successful; F.Check (Empty, "amd64", Enabled, Deadline, Result, Status); Expect (Status = Invalid_Input, "unsealed catalog"); No_Receipt;
   for I in 1 .. 4 loop
      declare Bad : constant String := (case I is when 1 => "all", when 2 => "any", when 3 => "source", when others => "AMD64"); begin
         Result := Successful; F.Check (Value, Bad, Enabled, Deadline, Result, Status); Expect (Status = Invalid_Input, "invalid native architecture"); No_Receipt;
      end;
   end loop;
   Result := Successful; F.Check (Value, "", Enabled, Deadline, Result, Status); Expect (Status = Invalid_Input, "empty native architecture"); No_Receipt;
   Result := Successful; F.Check (Value, "amd64", Enabled (1 .. 0), Deadline, Result, Status); Expect (Status = Invalid_Input, "empty architecture policy"); No_Receipt;
   Reordered := (Enabled (1), Enabled (1), Enabled (3));
   Result := Successful; F.Check (Value, "amd64", Reordered, Deadline, Result, Status); Expect (Status = Invalid_Input, "duplicate policy label"); No_Receipt;
   Result := Successful; F.Check (Value, "amd64", Enabled (2 .. 3), Deadline, Result, Status); Expect (Status = Invalid_Input, "native absent from policy"); No_Receipt;
   declare Excess : F.Architecture_List (1 .. F.Max_Architectures + 1); begin
      Result := Successful; F.Check (Value, "amd64", Excess, Deadline, Result, Status); Expect (Status = Exhausted, "architecture count cap"); No_Receipt;
   end;
   C.Clear (Value); X.Clear (Payload); MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Deb_Final_Set_Tests;
