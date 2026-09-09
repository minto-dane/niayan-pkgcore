-- SPDX-License-Identifier: MIT
with Ada.Containers.Ordered_Sets; with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix; with MC_SHA256;
with Pkg_Catalog_Store; with Pkg_Deb_Container;
package body Pkg_Catalog_Retention with SPARK_Mode => Off is
   package C renames Pkg_Selected_Catalog; package X renames Pkg_Payload_Index;
   package DC renames Pkg_Deb_Control; package DB renames Pkg_Deb_Container;
   package Objects is new Ada.Containers.Ordered_Sets (Digest);
   use type Interfaces.C.unsigned; use type Byte; use type Wide; use type MC_FS.Entry_Info;
   use type DC.Entry_Kind;
   Tag : constant String := "NIACLOS1";
   procedure Time_Left (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Time_Left;
   procedure Prepare (Store : in out MC_Store.Store; Catalog : Digest;
                      Deadline : Counter; Address : out Digest; Status : out Outcome) is
      Value : C.Catalog; Payload : X.Index; Members : Objects.Set;
      Item : C.Package_Record; Source : X.Package_Source; Claim : X.Claim;
      Envelope : DB.Envelope; Header : Bytes (1 .. Header_Size) := (others => 0);
      Hash : MC_SHA256.Context := MC_SHA256.Initialize; Expected : Digest;
      File : MC_FS.File; Writer : MC_Store.Writer;
      type Control_Access is access DC.Inventory;
      procedure Free is new Ada.Unchecked_Deallocation (DC.Inventory, Control_Access);
      Control : Control_Access := null;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Tick is
      begin Time_Left (Deadline, Status); Check; end Tick;
      procedure Cleanup is
      begin MC_FS.Close (File); MC_Store.Abort_Write (Writer); Free (Control); end Cleanup;
      procedure Include (Object : Digest) is
      begin
         Tick;
         if Object = Zero_Digest then Status := Corrupt; raise Interrupted; end if;
         if not Members.Contains (Object) then
            if Natural (Members.Length) = Max_Objects then Status := Exhausted; raise Interrupted; end if;
            Members.Insert (Object);
         end if;
      end Include;
   begin
      Address := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Tick;
      Pkg_Catalog_Store.Load (Store, Catalog, Deadline, Value, Payload, Status); Check;
      Include (Catalog); Control := new DC.Inventory;
      for I in 1 .. C.Package_Count (Value) loop
         Tick; C.Read_Package (Value, I, Item, Status); Check;
         X.Read_Package (Payload, I, Source, Status); Check;
         if Source.Original /= Item.Original then Status := Corrupt; raise Interrupted; end if;
         Include (Item.Original); Include (Item.Archive); Include (Source.Tar);
         DB.Inspect (Store, Item.Original, Deadline, Envelope, Status); Check;
         Include (Envelope.Items (Envelope.Data_Index).Content);
         DC.Stage (Store, Envelope, Deadline, Control.all, Status); Check;
         if Control.Archive /= Item.Archive or else Control.Control_Index = 0
           or else Control.Entries (Control.Control_Index).Content /= Item.Control
         then Status := Corrupt; raise Interrupted; end if;
         for Entry_Item of Control.Entries (1 .. Control.Count) loop
            if Entry_Item.Kind = DC.Regular then Include (Entry_Item.Content); end if;
         end loop;
      end loop;
      Free (Control);
      for I in 1 .. X.Claim_Count (Payload) loop
         Tick; X.Read_Claim (Payload, I, Claim, Status); Check;
         if Claim.Item.Values.Content /= Zero_Digest then Include (Claim.Item.Values.Content); end if;
         Include (Claim.Item.Values.Xattrs); Include (Claim.Item.Values.ACLs);
      end loop;
      -- Check deduplicated physical objects while the same CAS lock is held.
      for Object of Members loop
         Tick; MC_Store.Open_Object (Store, Object, File, Status); Check; MC_FS.Close (File);
      end loop;
      for I in Tag'Range loop Header (I) := Byte (Character'Pos (Tag (I))); end loop;
      Header (9 .. 40) := Catalog; Header (41 .. 72) := X.Fingerprint (Payload);
      MC_Codec.Put64 (Header, 73, Wide (Members.Length));
      MC_SHA256.Update (Hash, Header);
      for Object of Members loop Tick; MC_SHA256.Update (Hash, Object); end loop;
      Expected := MC_SHA256.Finish (Hash); Tick;
      MC_Store.Begin_Write (Store, Expected, Counter (Header_Size + 32 * Natural (Members.Length)), Writer, Status); Check;
      MC_Store.Write_Chunk (Writer, Header, Status); Check;
      for Object of Members loop Tick; MC_Store.Write_Chunk (Writer, Object, Status); Check; end loop;
      Tick; MC_Store.Finish_Write (Store, Writer, Status); Check; Tick;
      Address := Expected; Status := OK; Cleanup;
   exception
      when Interrupted => Cleanup; Address := Zero_Digest;
      when Storage_Error => Cleanup; Address := Zero_Digest; Status := Exhausted;
      when others => Cleanup; Address := Zero_Digest; Status := Indeterminate;
   end Prepare;
   procedure Verify (Store : in out MC_Store.Store; Catalog, Address : Digest;
                     Deadline : Counter; Status : out Outcome) is
      File, Object_File : MC_FS.File; Before, After : MC_FS.Entry_Info;
      Header : Bytes (1 .. Header_Size); Object, Previous, Expected : Digest := Zero_Digest;
      Count, Used : Natural; Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Tick is
      begin Time_Left (Deadline, Status); Check; end Tick;
      procedure Cleanup is
      begin MC_FS.Close (File); MC_FS.Close (Object_File); end Cleanup;
   begin
      Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Tick;
      if Catalog = Zero_Digest or else Address = Zero_Digest then Status := Invalid_Input; return; end if;
      MC_Store.Open_Object (Store, Address, File, Status); Check; Tick;
      MC_FS.Info (File, Before, Status); Check;
      if Before.Size > Max_Bytes then Status := Exhausted; raise Interrupted; end if;
      MC_FS.Read_At (File, 0, Header, Used, Status); Check;
      Status := Corrupt;
      if Used /= Header_Size then raise Interrupted; end if;
      for I in Tag'Range loop
         if Header (I) /= Byte (Character'Pos (Tag (I))) then Status := Unsupported; raise Interrupted; end if;
      end loop;
      if Header (9 .. 40) /= Catalog or else Header (41 .. 72) = Zero_Digest then raise Interrupted; end if;
      if MC_Codec.U64 (Header, 73) > Wide (Max_Objects) then Status := Exhausted; raise Interrupted; end if;
      Count := Natural (MC_Codec.U64 (Header, 73));
      if Count = 0 or else Before.Size /= Counter (Header_Size + 32 * Count) then raise Interrupted; end if;
      MC_SHA256.Update (Hash, Header);
      -- No reconstruction before every listed object has been checked. A lost
      -- derived object must be reported, even if it could be recreated later.
      for I in 1 .. Count loop
         Tick; MC_FS.Read_At (File, Counter (Header_Size + 32 * (I - 1)), Object, Used, Status); Check;
         if Used /= 32 or else Object <= Previous then Status := Corrupt; raise Interrupted; end if;
         Previous := Object; MC_SHA256.Update (Hash, Object);
         MC_Store.Open_Object (Store, Object, Object_File, Status); Check; MC_FS.Close (Object_File);
      end loop;
      MC_FS.Info (File, After, Status); Check;
      if Before /= After or else MC_SHA256.Finish (Hash) /= Address then Status := Corrupt; raise Interrupted; end if;
      MC_FS.Close (File); Tick;
      Prepare (Store, Catalog, Deadline, Expected, Status); Check;
      if Expected /= Address then Status := Corrupt; raise Interrupted; end if;
      Tick; Status := OK;
   exception
      when Interrupted => Cleanup;
      when Storage_Error => Cleanup; Status := Exhausted;
      when others => Cleanup; Status := Indeterminate;
   end Verify;
   procedure Pin (Store : in out MC_Store.Store; ID : Identity; Catalog : Digest;
                  Deadline : Counter; Address : out Digest; Status : out Outcome) is
      Expected : Digest;
   begin
      Address := Zero_Digest; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      if ID = Zero_Identity then Status := Invalid_Input; return; end if;
      Prepare (Store, Catalog, Deadline, Expected, Status); if Status /= OK then return; end if;
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      MC_Store.Pin (Store, ID, Expected, Status); if Status /= OK then return; end if;
      Time_Left (Deadline, Status); if Status = OK then Address := Expected; end if;
   exception
      when Storage_Error => Address := Zero_Digest; Status := Exhausted;
      when others => Address := Zero_Digest; Status := Indeterminate;
   end Pin;
   procedure Verify_Pin (Store : in out MC_Store.Store; ID : Identity;
                         Catalog, Address : Digest; Deadline : Counter; Status : out Outcome) is
   begin
      Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      if ID = Zero_Identity or else Catalog = Zero_Digest or else Address = Zero_Digest then Status := Invalid_Input; return; end if;
      MC_Store.Check_Pin (Store, ID, Address, Status); if Status /= OK then return; end if;
      Verify (Store, Catalog, Address, Deadline, Status);
   exception
      when Storage_Error => Status := Exhausted;
      when others => Status := Indeterminate;
   end Verify_Pin;
end Pkg_Catalog_Retention;
