-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Directories; with Ada.Strings.Fixed; with Ada.Text_IO;
with Interfaces.C;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store; with MC_Text;
with MC_Types; use MC_Types;
with Pkg_Deb_Final_Set; with Pkg_Deb_Payload; with Pkg_Deb_Transition;
with Pkg_Payload_Index; with Pkg_Selected_Catalog; with Test_Support; use Test_Support;
procedure Run_Deb_Transition_Tests with SPARK_Mode => Off is
   package T renames Pkg_Deb_Transition; package C renames Pkg_Selected_Catalog;
   package F renames Pkg_Deb_Final_Set; package P renames Pkg_Deb_Payload; package X renames Pkg_Payload_Index;
   use type Interfaces.C.unsigned; use type T.Failure_Kind; use type T.Change_Kind;
   Store : MC_Store.Store; Media : MC_FS.Root; Status : Outcome; Now, Deadline : Counter := 0;
   Baseline, Target, Unsealed : C.Catalog; Payload : X.Index; Source : P.Inventory;
   Result : T.Plan; Issue : T.Finding; Item, Saved_Item : T.Change;
   Enabled : F.Architecture_List (1 .. 3);
   Original, Before, After, Saved : Digest; Changes : Natural;
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
   function Token (Value : MC_Text.Value) return String is
     (if MC_Text.Length (Value) = 0 then "-" else MC_Text.Image (Value));
   procedure Load (Value : in out C.Catalog; Reverse_Order : Boolean) is
      Count : constant Natural := Natural'Value (Next);
      Selected : C.Selection (1 .. Count); File : MC_FS.File;
   begin
      Expect (Count <= 16, "bounded test selection"); C.Clear (Value); X.Clear (Payload);
      for I in Selected'Range loop
         declare Word : constant String := Next; Separator : constant Natural := Ada.Strings.Fixed.Index (Word, "="); begin
            Expect (Separator > 1, "original/control selection");
            MC_FS.Open_Read (Media, Word (Word'First .. Separator - 1), File, Status); Need ("fixture open");
            MC_Store.Import_File (Store, File, MC_Store.Max_Object_Size, Original, Status); Need ("fixture CAS import"); MC_FS.Close (File);
            Selected (I).Original := Original;
            MC_Hex.Decode (Word (Separator + 1 .. Word'Last), Selected (I).Control, Status); Need ("expected control hash");
         end;
      end loop;
      for Offset in 1 .. Count loop
         declare I : constant Positive := (if Reverse_Order then Count - Offset + 1 else Offset); begin
            P.Stage (Store, Selected (I).Original, Deadline, Source, Status); Need ("payload observation");
            X.Add (Payload, Source, Deadline, Status); Need ("source membership"); P.Clear (Source);
            C.Add (Value, Store, Selected (I).Original, Deadline, Status); Need ("candidate metadata");
         end;
      end loop;
      X.Seal (Payload, Deadline, Status); Need ("payload index");
      C.Seal (Value, Selected, Payload, Deadline, Status); Need ("sealed candidate");
   exception when others => MC_FS.Close (File); raise;
   end Load;
   procedure No_Plan is
   begin
      Expect (not T.Sealed (Result) and then T.Count (Result) = 0 and then T.Fingerprint (Result) = Zero_Digest
         and then T.Before_Hash (Result) = Zero_Digest and then T.After_Hash (Result) = Zero_Digest
         and then T.Endpoint_Hash (Result) = Zero_Digest, "failure clears all plan bindings");
      T.Read_Change (Result, 1, Item, Status);
      Expect (Status = Invalid_Input and then Item.Before_Original = Zero_Digest and then Item.After_Original = Zero_Digest
         and then MC_Text.Length (Item.Name) = 0, "failed plan exposes no change");
   end No_Plan;
   procedure Build is
   begin T.Build (Baseline, Target, "amd64", Enabled, Deadline, Result, Issue, Status); end Build;
begin
   Expect (Ada.Command_Line.Argument_Count = 2, "fresh CAS and transition fixture directory");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      Build; Expect (Status = Denied and then Issue.Kind = T.Not_Checked, "root refused before any catalog access");
      No_Plan; Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("fixture root");
   MC_Text.Set (Enabled (1), "amd64", Status); Need ("native architecture");
   MC_Text.Set (Enabled (2), "arm64", Status); Need ("foreign architecture");
   MC_Text.Set (Enabled (3), "i386", Status); Need ("third architecture");
   Ada.Text_IO.Open (Input, Ada.Text_IO.In_File, Ada.Command_Line.Argument (2) & "/cases.txt");
   while not Ada.Text_IO.End_Of_File (Input) loop
      Ada.Text_IO.Get_Line (Input, Line, Last); Expect (Last in 1 .. Line'Last - 1, "bounded complete case line"); Position := 1;
      MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 60_000;
      declare Name : constant String := Next; Expected : constant T.Failure_Kind := T.Failure_Kind'Value (Next);
         Start : constant Natural := Position;
      begin
         Load (Baseline, False); Load (Target, False);
         Before := C.Fingerprint (Baseline); After := C.Fingerprint (Target);
         if Expected /= T.None then
            T.Build (Baseline, Baseline, "amd64", Enabled, Deadline, Result, Issue, Status);
            Need ("seed previous successful plan before refusal");
            Expect (T.Sealed (Result), "previous successful plan exists");
         end if;
         Build;
         Ada.Text_IO.Put_Line ("TRANSITION " & Name & " " & T.Failure_Kind'Image (Issue.Kind) & " " & Outcome'Image (Status)
            & " " & MC_Hex.Encode (Before) & " " & MC_Hex.Encode (After)
            & " " & MC_Hex.Encode (T.Fingerprint (Result)) & " " & MC_Hex.Encode (T.Endpoint_Hash (Result))
            & Natural'Image (T.Count (Result)) & " " & MC_Hex.Encode (Issue.Before_Original) & " " & MC_Hex.Encode (Issue.After_Original)
            & " " & Boolean'Image (Issue.Essential_Lost) & " " & Boolean'Image (Issue.Protected_Lost)
            & " " & F.Finding_Kind'Image (Issue.Endpoint.Kind));
         Expect (Issue.Kind = Expected, Name & " expected diagnostic");
         Expect (C.Fingerprint (Baseline) = Before and then C.Fingerprint (Target) = After, "input catalogs unchanged");
         if Expected = T.None then
            Need ("valid ordinary transition"); Saved := T.Fingerprint (Result); Changes := T.Count (Result);
            Expect (T.Sealed (Result) and then Saved /= Zero_Digest and then T.Before_Hash (Result) = Before
               and then T.After_Hash (Result) = After and then T.Endpoint_Hash (Result) /= Zero_Digest, "complete plan binding");
            for I in 1 .. Changes loop
               T.Read_Change (Result, I, Item, Status); Need ("read change");
               Ada.Text_IO.Put_Line ("CHANGE " & Name & Natural'Image (I) & " " & T.Change_Kind'Image (Item.Kind)
                  & " " & Token (Item.Name) & " " & Token (Item.Architecture)
                  & " " & Token (Item.Before_Version) & " " & Token (Item.After_Version)
                  & " " & MC_Hex.Encode (Item.Before_Original) & " " & MC_Hex.Encode (Item.After_Original));
               if I = 1 then Saved_Item := Item; end if;
            end loop;
            T.Read_Change (Result, Changes + 1, Item, Status);
            Expect (Status = Invalid_Input and then Item.Before_Original = Zero_Digest and then MC_Text.Length (Item.Name) = 0, "out of range cleared");
            C.Clear (Baseline); C.Clear (Target); X.Clear (Payload);
            Expect (T.Fingerprint (Result) = Saved and then T.Count (Result) = Changes, "plan owns data beyond input lifetime");
            if Changes > 0 then
               T.Read_Change (Result, 1, Item, Status); Need ("read after input destruction");
               Expect (Item.Kind = Saved_Item.Kind and then Item.Before_Original = Saved_Item.Before_Original
                  and then Item.After_Original = Saved_Item.After_Original and then Token (Item.Name) = Token (Saved_Item.Name)
                  and then Token (Item.Architecture) = Token (Saved_Item.Architecture)
                  and then Token (Item.Before_Version) = Token (Saved_Item.Before_Version)
                  and then Token (Item.After_Version) = Token (Saved_Item.After_Version), "owned change remains identical");
            end if;
            Position := Start; Load (Baseline, True); Load (Target, True); Build; Need ("reverse insertion transition");
            Expect (T.Fingerprint (Result) = Saved and then T.Count (Result) = Changes, "insertion order does not affect delta");
            T.Build (Baseline, Target, "amd64", Enabled, 0, Result, Issue, Status); Expect (Status = Stale, "expired transition"); No_Plan;
            Build; Need ("restore successful plan");
            T.Build (Unsealed, Target, "amd64", Enabled, Deadline, Result, Issue, Status);
            Expect (Status = Invalid_Input, "unsealed baseline clears prior plan"); No_Plan;
            Build; Need ("restore again");
            T.Build (Baseline, Unsealed, "amd64", Enabled, Deadline, Result, Issue, Status);
            Expect (Status = Invalid_Input, "unsealed target clears prior plan"); No_Plan;
         else
            Expect (Status = (if Expected = T.Endpoint_Rejected then Conflict else Denied), "transition refusal status");
            No_Plan;
         end if;
         Cases := Cases + 1;
      end;
   end loop;
   Ada.Text_IO.Close (Input); Expect (Cases = 44, "complete transition matrix");
   T.Clear (Result); No_Plan; MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Deb_Transition_Tests;
