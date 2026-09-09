-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_Posix; with MC_SHA256; with MC_Text;
with Pkg_Catalog_Retention; with Pkg_Catalog_Store; with Pkg_Deb_Transition;
with Pkg_Selected_Catalog; with Pkg_Payload_Index;
package body Pkg_Generation_Intent with SPARK_Mode => Off is
   package GD renames Pkg_Generation_Descriptor;
   package DF renames Pkg_Deb_Final_Set; package DT renames Pkg_Deb_Transition;
   use type GD.Descriptor; use type Interfaces.C.unsigned; use type Word;
   Magic : constant Bytes := (78, 73, 65, 71, 73, 78, 84, 49);
   type Buffer_Access is access Bytes;
   type List_Access is access DF.Architecture_List;
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   procedure Free is new Ada.Unchecked_Deallocation (DF.Architecture_List, List_Access);
   type Data is record
      Root_ID : Identity := Zero_Identity;
      Before, Catalog, Closure, Proof, Binding : Digest := Zero_Digest;
      Native : MC_Text.Value;
   end record;
   procedure Time_Left (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      Status := Invalid_Input; if Deadline = Counter'Last then return; end if;
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Time_Left;
   function Update_Binding (Before, Catalog, Closure, Transition : Digest) return Digest is
      Wire : Bytes (1 .. 136);
   begin
      if Before = Zero_Digest or else Catalog = Zero_Digest or else Closure = Zero_Digest
        or else Transition = Zero_Digest then return Zero_Digest; end if;
      Wire (1 .. 8) := (78, 73, 65, 85, 80, 68, 48, 49);
      Wire (9 .. 40) := Before; Wire (41 .. 72) := Catalog;
      Wire (73 .. 104) := Closure; Wire (105 .. 136) := Transition;
      return MC_SHA256.Hash (Wire);
   end Update_Binding;
   function Initial_Binding (Root_ID : Identity; Catalog, Closure, Endpoint : Digest) return Digest is
      Wire : Bytes (1 .. 120);
   begin
      Wire (1 .. 8) := (78, 73, 65, 73, 78, 73, 48, 49);
      Wire (9 .. 24) := Root_ID; Wire (25 .. 56) := Catalog;
      Wire (57 .. 88) := Closure; Wire (89 .. 120) := Endpoint;
      return MC_SHA256.Hash (Wire);
   end Initial_Binding;
   procedure Evaluate (Store : in out MC_Store.Store; Root_ID : Identity; Before : GD.Descriptor;
      Before_Closure, Catalog, Closure : Digest; Native_Architecture : String;
      Enabled : DF.Architecture_List; Deadline : Counter;
      Proof, Binding : out Digest; Status : out Outcome) is
      Old, Target : Pkg_Selected_Catalog.Catalog; Payload : Pkg_Payload_Index.Index;
      Transition : DT.Plan; Issue : DT.Finding; Endpoint : DF.Verification;
   begin
      Proof := Zero_Digest; Binding := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      Status := Invalid_Input;
      if Root_ID = Zero_Identity or else Catalog = Zero_Digest or else Closure = Zero_Digest then return; end if;
      if Before = GD.Empty then
         if Before_Closure /= Zero_Digest then return; end if;
      elsif not GD.Valid (Before) or else Before.Root_ID /= Root_ID or else Before_Closure = Zero_Digest then
         Status := Denied; return;
      end if;
      Pkg_Catalog_Retention.Verify (Store, Catalog, Closure, Deadline, Status);
      if Status = OK and then Before /= GD.Empty then
         Pkg_Catalog_Retention.Verify (Store, Before.Catalog, Before_Closure, Deadline, Status);
      end if;
      if Status = OK then Pkg_Catalog_Store.Load (Store, Catalog, Deadline, Target, Payload, Status); end if;
      if Status = OK and then Before = GD.Empty then
         DF.Check (Target, Native_Architecture, Enabled, Deadline, Endpoint, Status);
         if Status = OK then
            Proof := DF.Fingerprint (Endpoint); Binding := Initial_Binding (Root_ID, Catalog, Closure, Proof);
         end if;
      elsif Status = OK then
         Pkg_Catalog_Store.Load (Store, Before.Catalog, Deadline, Old, Payload, Status);
         if Status = OK then DT.Build (Old, Target, Native_Architecture, Enabled, Deadline, Transition, Issue, Status); end if;
         if Status = OK then
            Proof := DT.Fingerprint (Transition);
            Binding := Update_Binding (MC_SHA256.Hash (GD.Encode (Before)), Catalog, Closure, Proof);
         end if;
      end if;
      if Status = OK then Time_Left (Deadline, Status); end if;
      if Status /= OK then Proof := Zero_Digest; Binding := Zero_Digest; end if;
   exception
      when Storage_Error => Proof := Zero_Digest; Binding := Zero_Digest; Status := Exhausted;
      when others => Proof := Zero_Digest; Binding := Zero_Digest; Status := Indeterminate;
   end Evaluate;
   procedure Prepare (Store : in out MC_Store.Store; Root_ID : Identity; Before : GD.Descriptor;
      Before_Closure, Catalog, Closure : Digest; Native_Architecture : String;
      Enabled : DF.Architecture_List; Deadline : Counter;
      Address, Binding : out Digest; Status : out Outcome) is
      Order : array (1 .. DF.Max_Architectures) of Positive := (others => 1);
      Wire : Buffer_Access := null; Proof, Expected_Binding, Saved : Digest;
      Size, Pos, Previous : Natural;
      procedure Text (Value : String) is
      begin
         for Ch of Value loop Pos := Pos + 1; Wire (Pos) := Byte (Character'Pos (Ch)); end loop;
      end Text;
   begin
      Address := Zero_Digest; Binding := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      Status := Invalid_Input;
      if Native_Architecture'Length not in 1 .. MC_Text.Max_Length or else Enabled'Length = 0 then return; end if;
      if Enabled'Length > DF.Max_Architectures then Status := Exhausted; return; end if;
      Evaluate (Store, Root_ID, Before, Before_Closure, Catalog, Closure, Native_Architecture,
         Enabled, Deadline, Proof, Expected_Binding, Status);
      if Status /= OK then return; end if;
      Size := Header_Size + Native_Architecture'Length;
      for I in 1 .. Enabled'Length loop
         Order (I) := Enabled'First + (I - 1);
         Size := Size + 4 + MC_Text.Length (Enabled (Order (I)));
         for J in reverse 2 .. I loop
            exit when MC_Text.Image (Enabled (Order (J - 1))) < MC_Text.Image (Enabled (Order (J)));
            Previous := Order (J - 1); Order (J - 1) := Order (J); Order (J) := Previous;
         end loop;
      end loop;
      Wire := new Bytes (1 .. Size); Wire.all := (others => 0);
      Wire (1 .. 8) := Magic; Wire (9 .. 24) := Root_ID;
      if Before /= GD.Empty then Wire (25 .. 56) := MC_SHA256.Hash (GD.Encode (Before)); end if;
      Wire (57 .. 88) := Catalog; Wire (89 .. 120) := Closure;
      Wire (121 .. 152) := Proof; Wire (153 .. 184) := Expected_Binding;
      MC_Codec.Put32 (Wire.all, 185, Word (Native_Architecture'Length));
      MC_Codec.Put32 (Wire.all, 189, Word (Enabled'Length)); Pos := Header_Size;
      Text (Native_Architecture);
      for I in 1 .. Enabled'Length loop
         MC_Codec.Put32 (Wire.all, Pos + 1, Word (MC_Text.Length (Enabled (Order (I))))); Pos := Pos + 4;
         Text (MC_Text.Image (Enabled (Order (I))));
      end loop;
      Time_Left (Deadline, Status);
      if Status = OK then MC_Store.Put (Store, Wire.all, Saved, Status); end if;
      if Status = OK then Time_Left (Deadline, Status); end if;
      if Status = OK then Address := Saved; Binding := Expected_Binding; end if;
      Free (Wire);
   exception
      when Storage_Error => Free (Wire); Address := Zero_Digest; Binding := Zero_Digest; Status := Exhausted;
      when others => Free (Wire); Address := Zero_Digest; Binding := Zero_Digest; Status := Indeterminate;
   end Prepare;
   procedure Read (Store : MC_Store.Store; Address : Digest; Deadline : Counter;
      Value : out Data; Enabled : out List_Access; Status : out Outcome) is
      Wire : Buffer_Access := null; Used, Pos, Count, Native_Length : Natural;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Text (Length : Natural; Result : out MC_Text.Value) is
         Content : String (1 .. Length);
      begin
         if Length = 0 or else Length > MC_Text.Max_Length or else Length > Used - Pos then
            Status := Corrupt; raise Interrupted;
         end if;
         for I in Content'Range loop Content (I) := Character'Val (Wire (Pos + I)); end loop;
         MC_Text.Set (Result, Content, Status); Check; Pos := Pos + Length;
      end Text;
      procedure Clear is
      begin Free (Wire); Free (Enabled); Value := (others => <>); end Clear;
   begin
      Value := (others => <>); Enabled := null; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Time_Left (Deadline, Status); Check;
      if Address = Zero_Digest then Status := Invalid_Input; return; end if;
      Wire := new Bytes (1 .. Max_Bytes);
      MC_Store.Read_Object (Store, Address, Wire.all, Used, Status); Check;
      Status := Corrupt; if Used < Header_Size then raise Interrupted; end if;
      if Wire (1 .. 8) /= Magic then Status := Unsupported; raise Interrupted; end if;
      if MC_Codec.U32 (Wire.all, 185) not in 1 .. Word (MC_Text.Max_Length)
        or else MC_Codec.U32 (Wire.all, 189) not in 1 .. Word (DF.Max_Architectures) then raise Interrupted; end if;
      Value.Root_ID := Wire (9 .. 24); Value.Before := Wire (25 .. 56); Value.Catalog := Wire (57 .. 88);
      Value.Closure := Wire (89 .. 120); Value.Proof := Wire (121 .. 152); Value.Binding := Wire (153 .. 184);
      if Value.Root_ID = Zero_Identity or else Value.Catalog = Zero_Digest or else Value.Closure = Zero_Digest
        or else Value.Proof = Zero_Digest or else Value.Binding = Zero_Digest then raise Interrupted; end if;
      Count := Natural (MC_Codec.U32 (Wire.all, 189)); Native_Length := Natural (MC_Codec.U32 (Wire.all, 185));
      Pos := Header_Size; Text (Native_Length, Value.Native);
      Enabled := new DF.Architecture_List (1 .. Count);
      for I in Enabled'Range loop
         Status := Corrupt;
         if Used - Pos < 4 or else MC_Codec.U32 (Wire.all, Pos + 1) > Word (MC_Text.Max_Length) then raise Interrupted; end if;
         declare Length : constant Natural := Natural (MC_Codec.U32 (Wire.all, Pos + 1)); begin
            Pos := Pos + 4; Text (Length, Enabled (I));
         end;
         if I > 1 and then MC_Text.Image (Enabled (I - 1)) >= MC_Text.Image (Enabled (I)) then
            Status := Corrupt; raise Interrupted;
         end if;
      end loop;
      if Pos /= Used then Status := Corrupt; raise Interrupted; end if;
      Time_Left (Deadline, Status); Check; Free (Wire);
   exception
      when Interrupted => Clear;
      when Storage_Error => Clear; Status := Exhausted;
      when others => Clear; Status := Indeterminate;
   end Read;
   procedure Check_Target (Store : MC_Store.Store; Address, Catalog, Closure : Digest;
      Deadline : Counter; Status : out Outcome) is
      Value : Data; Enabled : List_Access;
   begin
      Read (Store, Address, Deadline, Value, Enabled, Status);
      if Status = OK and then (Value.Catalog /= Catalog or else Value.Closure /= Closure) then Status := Conflict; end if;
      Free (Enabled);
   exception when others => Free (Enabled); Status := Indeterminate;
   end Check_Target;
   procedure Verify (Store : in out MC_Store.Store; Address : Digest; Root_ID : Identity;
      Before : GD.Descriptor; Before_Closure, Catalog, Closure : Digest;
      Deadline : Counter; Binding : out Digest; Status : out Outcome) is
      Value : Data; Enabled : List_Access; Proof, Expected_Binding : Digest;
      Expected_Before : Digest := Zero_Digest;
   begin
      Binding := Zero_Digest; Read (Store, Address, Deadline, Value, Enabled, Status);
      if Status = OK and then Before /= GD.Empty then Expected_Before := MC_SHA256.Hash (GD.Encode (Before)); end if;
      if Status = OK and then (Value.Root_ID /= Root_ID or else Value.Before /= Expected_Before
        or else Value.Catalog /= Catalog or else Value.Closure /= Closure) then Status := Denied; end if;
      if Status = OK then
         Evaluate (Store, Root_ID, Before, Before_Closure, Catalog, Closure,
            MC_Text.Image (Value.Native), Enabled.all, Deadline, Proof, Expected_Binding, Status);
      end if;
      if Status = OK and then (Proof /= Value.Proof or else Expected_Binding /= Value.Binding) then Status := Conflict; end if;
      if Status = OK then Binding := Expected_Binding; end if;
      Free (Enabled);
   exception
      when Storage_Error => Free (Enabled); Binding := Zero_Digest; Status := Exhausted;
      when others => Free (Enabled); Binding := Zero_Digest; Status := Indeterminate;
   end Verify;
end Pkg_Generation_Intent;
