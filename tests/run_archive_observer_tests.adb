-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO;
with Interfaces.C;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store;
with MC_Types; use MC_Types;
with Pkg_Archive_Observer; with Pkg_Archive_Supply;
with Pkg_Catalog_Retention; with Pkg_Catalog_Store; with Pkg_Deb_Payload;
with Pkg_Payload_Index; with Pkg_Selected_Catalog; with Pkg_Supply_Map; with Pkg_Supply_Policy;
with Test_Support; use Test_Support;
procedure Run_Archive_Observer_Tests with SPARK_Mode => Off is
   use type Word; use type Interfaces.C.unsigned;
   Store, Competing : MC_Store.Store;
   Media : MC_FS.Root;
   File : MC_FS.File;
   Status : Outcome;
   Trusted : Pkg_Archive_Supply.Authority :=
     (Scope => (others => 91), Key => (others => 93), Minimum_Epoch => 7, Maximum_Age => 300);
   Original, Control, InRelease, Index, Keyring, Other, Receipt, Policy, Binding : Digest := Zero_Digest;
   ID : constant Digest := (others => 94);
   Boot, Now, Deadline : Counter;
   Used : Natural;
   Observer_UID : Word := Word (MC_Posix.Euid) + 1;
   Held : Integer;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Import (Name : String; Hash : out Digest) is
   begin
      MC_FS.Open_Read (Media, Name, File, Status); Need ("open " & Name);
      MC_Store.Import_File (Store, File, MC_Store.Max_Object_Size, Hash, Status); Need ("import " & Name);
      MC_FS.Close (File);
   end Import;
   procedure Call (At_Deadline : Counter; Index_Path : String := "main/binary-amd64/Packages.xz";
                   Deb_Path : String := "pool/test.deb") is
   begin
      Receipt := ID; Policy := ID;
      Pkg_Archive_Observer.Observe (Store, ID, Original, Control, InRelease, Index, Keyring,
         Index_Path, Deb_Path, Observer_UID, Trusted, At_Deadline, Receipt, Policy, Status);
      Expect ((Status = OK and then Receipt /= Zero_Digest and then Policy /= Zero_Digest)
              or else (Status /= OK and then Receipt = Zero_Digest and then Policy = Zero_Digest), "output binding or both zero");
   end Call;
   procedure Exclusion is
   begin
      Expect (MC_Store.Native_Reservation (Store) = Held, "same native reservation FD");
      MC_Store.Open (Ada.Command_Line.Argument (1), Competing, Status);
      Expect (Status = Conflict, "competing CAS writer excluded");
      MC_Store.Close (Competing);
   end Exclusion;
   procedure Bind_Plan is
      Catalog : Pkg_Selected_Catalog.Catalog;
      Payload : Pkg_Payload_Index.Index;
      Inventory : Pkg_Deb_Payload.Inventory;
      Selection : constant Pkg_Selected_Catalog.Selection := (1 => (Original, Control));
      Sources : constant Pkg_Supply_Map.Sources := (1 => (Original, Control, Receipt));
      Authorities : constant Pkg_Supply_Map.Authorities := (1 => Trusted);
      Empty_Sources : Pkg_Supply_Map.Sources (1 .. 0);
      Target : Pkg_Supply_Map.Context;
      Map, Retained_Policy, Rejected : Digest;
      Until_Time : Counter;
   begin
      Target.Root_ID := (others => 95); -- A planning fixture, not an accepted root.
      Pkg_Deb_Payload.Stage (Store, Original, Deadline, Inventory, Status); Need ("native payload");
      Pkg_Payload_Index.Add (Payload, Inventory, Deadline, Status); Need ("payload index");
      Pkg_Selected_Catalog.Add (Catalog, Store, Original, Deadline, Status); Need ("native catalog");
      Pkg_Payload_Index.Seal (Payload, Deadline, Status); Need ("seal payload");
      Pkg_Selected_Catalog.Seal (Catalog, Selection, Payload, Deadline, Status); Need ("seal selection");
      Pkg_Catalog_Store.Save (Store, Catalog, Deadline, Target.Catalog, Status); Need ("save catalog");
      Pkg_Catalog_Retention.Prepare (Store, Target.Catalog, Deadline, Target.Closure, Status); Need ("retain closure");
      MC_Clock.Realtime_Seconds (Now, Status); Need ("planning UTC");
      Pkg_Supply_Map.Prepare (Store, Target, Sources, Authorities, Now, Deadline, Map, Until_Time, Status); Need ("bind observer to supply map");
      Expect (Until_Time > Now, "live supply map expiry");
      Pkg_Supply_Map.Verify (Store, Map, Target, Authorities, Now, Deadline, Until_Time, Status); Need ("fresh supply map verification");
      Pkg_Supply_Policy.Prepare (Store, Map, Target, Authorities, Now, Deadline, Retained_Policy, Until_Time, Status); Need ("retain supply policy");
      Pkg_Supply_Policy.Verify_New (Store, Retained_Policy, Target, Authorities, Now, Deadline, Until_Time, Status); Need ("verify retained policy independently");
      Pkg_Supply_Policy.Check_Retention (Store, Retained_Policy, Target.Catalog, Target.Closure, Deadline, Status); Need ("complete supply retention");
      Pkg_Supply_Map.Prepare (Store, Target, Empty_Sources, Authorities, Now, Deadline, Rejected, Until_Time, Status);
      Expect (Status /= OK and then Rejected = Zero_Digest and then Until_Time = 0, "new original cannot omit observer receipt");
      Ada.Text_IO.Put_Line ("SUPPLY_MAP " & MC_Hex.Encode (Map));
      Ada.Text_IO.Put_Line ("SUPPLY_RETAINED_POLICY " & MC_Hex.Encode (Retained_Policy));
   end Bind_Plan;
begin
   Expect (Ada.Command_Line.Argument_Count in 2 | 6, "private CAS and media; optional observer UID/index/DEB/mode");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      Call (0); Expect (Status = Denied, "root refused before socket/store access"); Report; return;
   end if;
   MC_Clock.Boottime_Milliseconds (Boot, Status); Need ("boottime"); Deadline := Boot + 125_000;
   Original := ID; Control := ID; InRelease := ID; Index := ID; Keyring := ID;
   Call (Deadline); Expect (Status = Invalid_Input, "closed store refused");
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("fresh test store");
   Held := MC_Store.Native_Reservation (Store); Exclusion;
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("media");
   if Ada.Command_Line.Argument_Count = 2 then
      Import ("empty.deb", Original);
      Control := ID; InRelease := ID; Index := ID; Keyring := ID;
      Call (0); Expect (Status = Stale, "expired deadline refused");
      Call (Counter'Last); Expect (Status = Invalid_Input, "unbounded deadline refused");
      Call (Deadline, Deb_Path => "bad" & Character'Val (0)); Expect (Status = Invalid_Input, "embedded NUL refused");
      Observer_UID := 0; Call (Deadline); Expect (Status = Invalid_Input, "root observer refused");
      Observer_UID := Word (MC_Posix.Euid); Call (Deadline); Expect (Status = Invalid_Input, "self observer refused");
      Observer_UID := Word (MC_Posix.Euid) + 1;
      Call (Deadline); Expect (Status /= OK, "missing retained originals refused before network");
   else
      Observer_UID := Word'Value (Ada.Command_Line.Argument (3));
      Import ("original.deb", Original); Import ("InRelease", InRelease);
      Import ("Packages", Index); Import ("keyring", Keyring);
      Import ("public-key", Other); MC_Store.Read_Object (Store, Other, Trusted.Key, Used, Status); Need ("public pin");
      Expect (Used = 32, "public pin size");
      Import ("scope", Other); MC_Store.Read_Object (Store, Other, Trusted.Scope, Used, Status); Need ("scope pin");
      Expect (Used = 32, "scope size");
      Import ("control", Control);
      if Ada.Command_Line.Argument (6) = "wrong-control" then Control := Keyring; end if;
      Call (Deadline, Ada.Command_Line.Argument (4), Ada.Command_Line.Argument (5));
      if Ada.Command_Line.Argument (6) = "accepted" then
         Need ("native observer");
         MC_Clock.Realtime_Seconds (Now, Status); Need ("current UTC");
         Pkg_Archive_Supply.Verify_Original (Store, Receipt, Original, Control, Trusted, Now, Deadline, Binding, Status);
         Need ("fresh native verification"); Expect (Binding = Receipt, "retained receipt binding");
         MC_Store.Open_Object (Store, Policy, File, Status); Need ("retained policy"); MC_FS.Close (File);
         Ada.Text_IO.Put_Line ("SUPPLY_RECEIPT " & MC_Hex.Encode (Receipt));
         Ada.Text_IO.Put_Line ("SUPPLY_POLICY " & MC_Hex.Encode (Policy));
         Bind_Plan;
      else
         Expect (Ada.Command_Line.Argument (6) in "denied" | "wrong-control", "explicit rejection mode");
         Expect (Status /= OK, "observer rejected without stale bindings");
      end if;
   end if;
   Exclusion;
   MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception
   when others => MC_FS.Close (File); MC_FS.Close (Media); MC_Store.Close (Store); MC_Store.Close (Competing); raise;
end Run_Archive_Observer_Tests;
