-- SPDX-License-Identifier: MIT
-- Scoped keys and opaque upstream metadata here are synthetic test inputs.
-- The integration bridge separately issues from real TUF/OpenPGP fixtures.
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO; with Ada.Unchecked_Deallocation;
with Interfaces.C; with System;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_Store;
with MC_Types; use MC_Types;
with Pkg_Archive_Supply; with Pkg_Deb_Metadata; with Test_Support; use Test_Support;
procedure Run_Archive_Supply_Tests with SPARK_Mode => Off is
   package Supply renames Pkg_Archive_Supply;
   use type Interfaces.C.int; use type Interfaces.C.unsigned; use type Interfaces.C.unsigned_long_long;
   use type Byte; use type Wide; use type MC_FS.Entry_Kind;
   Store : MC_Store.Store; Media, CAS_Root : MC_FS.Root; File : MC_FS.File;
   Status : Outcome; Now, Boot, Deadline : Counter;
   Trusted, Altered : Supply.Authority;
   Original, Control, Address, Good, Binding, Other : Digest;
   Wire, Saved : Bytes (1 .. Supply.Wire_Size) := (others => 0);
   Refs : array (1 .. 6) of Digest := (others => Zero_Digest);
   SK : Bytes (1 .. 64); Seed : constant Digest := (others => 93);
   Used : Natural;
   type Observation_Access is access Pkg_Deb_Metadata.Observation;
   Observed : Observation_Access := null;
   procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Observation_Access);
   function Keypair (PK, SK, Seed : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_sign_seed_keypair";
   function Sign (Signature, Length, Message : System.Address;
      Size : Interfaces.C.unsigned_long_long; SK : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_sign_detached";
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Import (Name : String; Hash : out Digest) is
   begin
      MC_FS.Open_Read (Media, Name, File, Status); Need ("fixture open " & Name);
      MC_Store.Import_File (Store, File, MC_Store.Max_Object_Size, Hash, Status); Need ("fixture import"); MC_FS.Close (File);
   end Import;
   function Object_Path (Hash : Digest) return String is
      Hex : constant String := MC_Hex.Encode (Hash);
   begin return "objects/" & Hex (1 .. 2) & "/" & Hex (3 .. 64); end Object_Path;
   procedure Sign_Wire (Domain : String := "NiaOS/archive-supply/v1") is
      Message : Bytes (1 .. 2 + Domain'Length + Supply.Body_Size);
      Position : Natural := 2;
      Size : aliased Interfaces.C.unsigned_long_long := 0;
   begin
      MC_Codec.Put16 (Message, 1, Domain'Length);
      for Ch of Domain loop Position := Position + 1; Message (Position) := Byte (Character'Pos (Ch)); end loop;
      Message (Position + 1 .. Message'Last) := Wire (1 .. Supply.Body_Size);
      Expect (Sign (Wire (Supply.Body_Size + 1)'Address, Size'Address, Message'Address,
         Message'Length, SK'Address) = 0 and then Size = 64, "test signature");
   end Sign_Wire;
   procedure Verify (Receipt : Digest; Expected : Outcome := OK) is
   begin
      Binding := Good;
      Supply.Verify_Original (Store, Receipt, Original, Control, Trusted, Now, Deadline, Binding, Status);
      Expect (Status = Expected, "receipt result " & Outcome'Image (Status));
      Expect (Binding = (if Status = OK then Receipt else Zero_Digest), "no stale successful binding");
   end Verify;
   procedure Reject (Data : Bytes; Label_Text : String) is
   begin
      MC_Store.Put (Store, Data, Address, Status); Need ("retain rejection fixture"); Binding := Good;
      Supply.Verify_Original (Store, Address, Original, Control, Trusted, Now, Deadline, Binding, Status);
      Expect (Status /= OK and then Binding = Zero_Digest, "reject " & Label_Text);
   end Reject;
   procedure Policy_Reject (Policy : Supply.Authority; At_Time, At_Deadline : Counter; Label_Text : String) is
   begin
      Binding := Good;
      Supply.Verify_Original (Store, Good, Original, Control, Policy, At_Time, At_Deadline, Binding, Status);
      Expect (Status /= OK and then Binding = Zero_Digest, Label_Text);
   end Policy_Reject;
   procedure External_Fixture is
   begin
      Expect (Ada.Command_Line.Argument (3) = "external", "explicit external fixture mode");
      Import ("original.deb", Original); Import ("control", Control);
      Import ("policy", Other); Import ("InRelease", Other); Import ("Packages", Other); Import ("keyring", Other);
      Import ("public-key", Other); MC_Store.Read_Object (Store, Other, Trusted.Key, Used, Status); Need ("observer public key");
      Expect (Used = 32, "key size");
      Import ("scope", Other); MC_Store.Read_Object (Store, Other, Trusted.Scope, Used, Status); Need ("independent scope");
      Expect (Used = 32, "scope size");
      Trusted.Minimum_Epoch := 7; Trusted.Maximum_Age := 300;
      Import ("receipt", Good); Verify (Good);
      Ada.Text_IO.Put_Line ("SUPPLY_RECEIPT " & MC_Hex.Encode (Binding));
      Ada.Text_IO.Put_Line ("SUPPLY_ORIGINAL " & MC_Hex.Encode (Original));
      Ada.Text_IO.Put_Line ("SUPPLY_CONTROL " & MC_Hex.Encode (Control));
   end External_Fixture;
begin
   Expect (Ada.Command_Line.Argument_Count in 2 .. 3, "fresh store and fixture directory");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      Supply.Verify_Original (Store, Zero_Digest, Zero_Digest, Zero_Digest, Trusted, 0, 0, Binding, Status);
      Expect (Status = Denied and then Binding = Zero_Digest, "UID0 rejected before store access");
      Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("media");
   MC_Clock.Boottime_Milliseconds (Boot, Status); Need ("boottime"); Deadline := Boot + 600_000;
   MC_Clock.Realtime_Seconds (Now, Status); Need ("UTC");
   if Ada.Command_Line.Argument_Count = 3 then
      External_Fixture; MC_FS.Close (Media); MC_Store.Close (Store); Report; return;
   end if;
   Import ("empty.deb", Original);
   Observed := new Pkg_Deb_Metadata.Observation;
   Pkg_Deb_Metadata.Inspect (Store, Original, Deadline, Observed.all, Status); Need ("original control");
   Control := Observed.Control; Free (Observed);
   Trusted := (Scope => (others => 91), Minimum_Epoch => 7, Maximum_Age => 3_600, others => <>);
   Expect (Keypair (Trusted.Key'Address, SK'Address, Seed'Address) = 0, "synthetic observer key");
   for I in Refs'Range loop
      MC_Store.Put (Store, (1 => Byte (I)), Refs (I), Status); Need ("synthetic upstream object");
   end loop;
   Refs (2) := Original; Refs (3) := Control;
   Wire (1 .. 8) := (78, 73, 65, 83, 85, 80, 48, 49); Wire (9 .. 40) := Trusted.Scope;
   for I in Refs'Range loop Wire (41 + 32 * (I - 1) .. 72 + 32 * (I - 1)) := Refs (I); end loop;
   MC_Codec.Put64 (Wire, 233, 7); MC_Codec.Put64 (Wire, 241, Wide (Now - 10));
   MC_Codec.Put64 (Wire, 249, Wide (Now + 600)); Sign_Wire; Saved := Wire;
   MC_Store.Put (Store, Wire, Good, Status); Need ("signed original supply receipt"); Verify (Good);
   MC_Store.Close (Store); MC_Store.Open (Ada.Command_Line.Argument (1), Store, Status); Need ("reopen CAS"); Verify (Good);
   Reject (Wire (1 .. 0), "empty"); Reject (Wire (1 .. 255), "body only");
   Reject (Wire (1 .. 319), "truncated signature"); Reject (Wire & Byte'(0), "trailing byte");
   for I in Wire'Range loop
      Wire := Saved; Wire (I) := Wire (I) xor 1; Reject (Wire, "each damaged byte");
   end loop;
   Wire := Saved; Sign_Wire ("NiaOS/other-domain/v1"); Reject (Wire, "wrong signed domain");
   for I in 0 .. 6 loop
      Wire := Saved; Wire (9 + 32 * I .. 40 + 32 * I) := Zero_Digest; Sign_Wire;
      Reject (Wire, "signed zero digest");
   end loop;
   for I in 0 .. 2 loop
      Wire := Saved; MC_Codec.Put64 (Wire, 233 + 8 * I, 0); Sign_Wire; Reject (Wire, "zero time or epoch");
      MC_Codec.Put64 (Wire, 233 + 8 * I, 2 ** 53); Sign_Wire; Reject (Wire, "out-of-range time or epoch");
   end loop;
   Wire := Saved; MC_Codec.Put64 (Wire, 233, 6); Sign_Wire; Reject (Wire, "old epoch");
   Wire := Saved; MC_Codec.Put64 (Wire, 249, Wide (Now - 10)); Sign_Wire; Reject (Wire, "empty lifetime");
   Wire := Saved; MC_Codec.Put64 (Wire, 249, Wide (Now - 11)); Sign_Wire; Reject (Wire, "reversed lifetime");
   Wire := Saved; MC_Codec.Put64 (Wire, 249, Wide (Now + 3_600)); Sign_Wire; Reject (Wire, "excessive lifetime");
   Altered := Trusted; Altered.Key (1) := Altered.Key (1) xor 1; Policy_Reject (Altered, Now, Deadline, "wrong trusted key");
   Altered.Key := (others => 0); Policy_Reject (Altered, Now, Deadline, "missing independent key");
   Altered := Trusted; Altered.Scope (1) := Altered.Scope (1) xor 1; Policy_Reject (Altered, Now, Deadline, "other scope");
   Altered.Scope := Zero_Digest; Policy_Reject (Altered, Now, Deadline, "missing scope");
   Altered := Trusted; Altered.Minimum_Epoch := 8; Policy_Reject (Altered, Now, Deadline, "higher independent floor");
   Altered.Minimum_Epoch := 0; Policy_Reject (Altered, Now, Deadline, "missing independent floor");
   Altered := Trusted; Altered.Maximum_Age := 5; Policy_Reject (Altered, Now, Deadline, "observation too old");
   Altered.Maximum_Age := 0; Policy_Reject (Altered, Now, Deadline, "missing maximum age");
   Altered.Maximum_Age := 3_601; Policy_Reject (Altered, Now, Deadline, "excessive maximum age");
   Policy_Reject (Trusted, Now - 11, Deadline, "future observation");
   Policy_Reject (Trusted, Now + 600, Deadline, "exclusive receipt expiry");
   Policy_Reject (Trusted, Now, 0, "elapsed deadline");
   Policy_Reject (Trusted, Now, Counter'Last, "infinite deadline");
   Policy_Reject (Trusted, 0, Deadline, "missing independent time");
   Policy_Reject (Trusted, 2 ** 53, Deadline, "out-of-range independent time");
   -- A valid signature cannot make a different native control match this DEB.
   Wire := Saved; Wire (105 .. 136) := Refs (1); Sign_Wire;
   MC_Store.Put (Store, Wire, Address, Status); Need ("signed wrong-control assertion");
   Supply.Verify_Original (Store, Address, Original, Refs (1), Trusted, Now, Deadline, Binding, Status);
   Expect (Status = Conflict and then Binding = Zero_Digest, "native control independently reobserved");
   Wire := Saved; Wire (73 .. 104) := Refs (1); Sign_Wire;
   MC_Store.Put (Store, Wire, Address, Status); Need ("signed invalid DEB assertion");
   Supply.Verify_Original (Store, Address, Refs (1), Control, Trusted, Now, Deadline, Binding, Status);
   Expect (Status /= OK and then Binding = Zero_Digest, "original must really be a native DEB");
   MC_FS.Open_Root (Ada.Command_Line.Argument (1), CAS_Root, Status, Private_Only => True); Need ("private fault root");
   for Hash of Refs loop
      MC_FS.Rename (CAS_Root, Object_Path (Hash), "held-object", True, Status); Need ("withhold required object");
      Binding := Good;
      Supply.Verify_Original (Store, Good, Original, Control, Trusted, Now, Deadline, Binding, Status);
      Expect (Status /= OK and then Binding = Zero_Digest, "every missing reference refused");
      declare Info : MC_FS.Entry_Info; begin
         MC_FS.Stat (CAS_Root, Object_Path (Hash), Info, Status); Need ("inspect missing reference");
         Expect (Info.Kind = MC_FS.Absent, "missing raw control or original not regenerated");
      end;
      MC_FS.Rename (CAS_Root, "held-object", Object_Path (Hash), True, Status); Need ("restore required object"); Verify (Good);
   end loop;
   MC_FS.Close (CAS_Root); MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => Free (Observed); MC_FS.Close (File); MC_FS.Close (CAS_Root); MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Archive_Supply_Tests;
