-- SPDX-License-Identifier: MIT
with Ada.Containers.Vectors; with Ada.Containers.Indefinite_Ordered_Maps;
with Ada.Strings.Unbounded; with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_Posix; with MC_SHA256; with Pkg_Deb_Versions;
package body Pkg_Deb_Transition with SPARK_Mode => Off is
   package C renames Pkg_Selected_Catalog; package F renames Pkg_Deb_Final_Set;
   use Ada.Strings.Unbounded; use type Interfaces.C.unsigned;
   type Stored_Change is record
      Kind : Change_Kind;
      Name, Architecture, Before_Version, After_Version : Unbounded_String;
      Before_Original, After_Original : Digest;
   end record;
   package Changes is new Ada.Containers.Vectors (Positive, Stored_Change);
   type Pair is record
      Old_Position, New_Position : Natural := 0;
   end record;
   package Pairs is new Ada.Containers.Indefinite_Ordered_Maps (String, Pair);
   type Data is record
      Items : Changes.Vector;
      Before, After, Endpoint, Hash : Digest := Zero_Digest;
      Complete : Boolean := False;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Plan) is
   begin Free (Value.State); end Clear;
   overriding procedure Finalize (Value : in out Plan) is
   begin Clear (Value); end Finalize;
   function Sealed (Value : Plan) return Boolean is (Value.State /= null and then Value.State.Complete);
   function Count (Value : Plan) return Natural is (if Sealed (Value) then Natural (Value.State.Items.Length) else 0);
   function Before_Hash (Value : Plan) return Digest is (if Sealed (Value) then Value.State.Before else Zero_Digest);
   function After_Hash (Value : Plan) return Digest is (if Sealed (Value) then Value.State.After else Zero_Digest);
   function Endpoint_Hash (Value : Plan) return Digest is (if Sealed (Value) then Value.State.Endpoint else Zero_Digest);
   function Fingerprint (Value : Plan) return Digest is (if Sealed (Value) then Value.State.Hash else Zero_Digest);
   procedure Build (Before, After : C.Catalog; Native_Architecture : String;
                    Enabled : F.Architecture_List; Deadline : Counter; Result : in out Plan;
                    Issue : out Finding; Status : out Outcome) is
      Identities : Pairs.Map; Old, New_Item : C.Package_Record;
      Endpoint : F.Verification; Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Interrupted : exception;
      procedure Time_Left is
         Now : Counter;
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
         if Status /= OK then raise Interrupted; end if;
      end Time_Left;
      procedure Number (N : Wide) is
         B : Bytes (1 .. 8);
      begin MC_Codec.Put64 (B, 1, N); MC_SHA256.Update (Hash, B); end Number;
      procedure Text (S : String) is
         B : Bytes (1 .. S'Length);
      begin
         Number (Wide (S'Length));
         for I in S'Range loop B (I - S'First + 1) := Byte (Character'Pos (S (I))); end loop;
         MC_SHA256.Update (Hash, B);
      end Text;
      procedure Index_Catalog (Value : C.Catalog; Baseline : Boolean) is
         Item : C.Package_Record; Positions : Pair;
      begin
         for I in 1 .. C.Package_Count (Value) loop
            Time_Left; C.Read_Package (Value, I, Item, Status); if Status /= OK then raise Interrupted; end if;
            -- NUL is excluded from both labels and sorts before every label byte,
            -- so the composite key preserves tuple ordering even for prefix names.
            declare Key : constant String := MC_Text.Image (Item.Identity.Name) & Character'Val (0) & MC_Text.Image (Item.Identity.Architecture); begin
               Positions := (others => <>);
               if Identities.Contains (Key) then Positions := Identities.Element (Key); end if;
               if Baseline then Positions.Old_Position := I; else Positions.New_Position := I; end if;
               Identities.Include (Key, Positions);
            end;
         end loop;
      end Index_Catalog;
   begin
      Clear (Result); Issue := (others => <>); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Time_Left;
      if not C.Sealed (Before) or else not C.Sealed (After) then Status := Invalid_Input; return; end if;
      F.Check (After, Native_Architecture, Enabled, Deadline, Endpoint, Status);
      if Status /= OK then Issue.Kind := Endpoint_Rejected; Issue.Endpoint := F.Diagnostic (Endpoint); return; end if;
      if not F.Passed (Endpoint) or else F.Catalog_Hash (Endpoint) /= C.Fingerprint (After) then Status := Corrupt; return; end if;
      Index_Catalog (Before, True); Index_Catalog (After, False);
      Result.State := new Data;
      for Cursor in Identities.Iterate loop
         Time_Left; Old := (others => <>); New_Item := (others => <>);
         declare Positions : constant Pair := Pairs.Element (Cursor); begin
            if Positions.Old_Position /= 0 then
               C.Read_Package (Before, Positions.Old_Position, Old, Status); if Status /= OK then raise Interrupted; end if;
            end if;
            if Positions.New_Position /= 0 then
               C.Read_Package (After, Positions.New_Position, New_Item, Status); if Status /= OK then raise Interrupted; end if;
            end if;
            if (Old.Identity.Essential and then not New_Item.Identity.Essential)
              or else (Old.Identity.Protected_Package and then not New_Item.Identity.Protected_Package) then
               Issue := (Kind => Protection_Migration_Required, Before_Original => Old.Original,
                  After_Original => New_Item.Original,
                  Essential_Lost => Old.Identity.Essential and then not New_Item.Identity.Essential,
                  Protected_Lost => Old.Identity.Protected_Package and then not New_Item.Identity.Protected_Package,
                  others => <>);
               Status := Denied; Clear (Result); return;
            end if;
            if Old.Original /= New_Item.Original then
               declare
                  Item : Stored_Change;
                  Identity : constant C.Package_Record := (if Positions.New_Position /= 0 then New_Item else Old);
               begin
                  if Old.Original = Zero_Digest then Item.Kind := Added;
                  elsif New_Item.Original = Zero_Digest then Item.Kind := Removed;
                  else
                     case Pkg_Deb_Versions.Compare (MC_Text.Image (New_Item.Identity.Version), MC_Text.Image (Old.Identity.Version)) is
                        when Pkg_Deb_Versions.Newer => Item.Kind := Upgraded;
                        when Pkg_Deb_Versions.Older => Item.Kind := Downgraded;
                        when Pkg_Deb_Versions.Equal => Item.Kind := Repacked;
                     end case;
                  end if;
                  Item.Name := To_Unbounded_String (MC_Text.Image (Identity.Identity.Name));
                  Item.Architecture := To_Unbounded_String (MC_Text.Image (Identity.Identity.Architecture));
                  Item.Before_Version := To_Unbounded_String (MC_Text.Image (Old.Identity.Version));
                  Item.After_Version := To_Unbounded_String (MC_Text.Image (New_Item.Identity.Version));
                  Item.Before_Original := Old.Original; Item.After_Original := New_Item.Original;
                  if Natural (Result.State.Items.Length) = Max_Changes then Status := Exhausted; raise Interrupted; end if;
                  Result.State.Items.Append (Item);
               end;
            end if;
         end;
      end loop;
      Result.State.Before := C.Fingerprint (Before); Result.State.After := C.Fingerprint (After);
      Result.State.Endpoint := F.Fingerprint (Endpoint);
      Text ("NIADTRANS1"); MC_SHA256.Update (Hash, Result.State.Before); MC_SHA256.Update (Hash, Result.State.After);
      MC_SHA256.Update (Hash, Result.State.Endpoint); Number (Wide (Result.State.Items.Length));
      for Item of Result.State.Items loop
         Time_Left; Number (Change_Kind'Pos (Item.Kind)); Text (To_String (Item.Name)); Text (To_String (Item.Architecture));
         Text (To_String (Item.Before_Version)); Text (To_String (Item.After_Version));
         MC_SHA256.Update (Hash, Item.Before_Original); MC_SHA256.Update (Hash, Item.After_Original);
      end loop;
      Time_Left; Result.State.Hash := MC_SHA256.Finish (Hash); Result.State.Complete := True;
      Issue.Kind := None; Status := OK;
   exception
      when Interrupted => Clear (Result); Issue := (others => <>);
      when Storage_Error => Clear (Result); Issue := (others => <>); Status := Exhausted;
      when others => Clear (Result); Issue := (others => <>); Status := Indeterminate;
   end Build;
   procedure Read_Change (Value : Plan; Position : Positive; Item : out Change; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position > Count (Value) then return; end if;
      declare Stored : constant Stored_Change := Value.State.Items.Element (Position); begin
         MC_Text.Set (Item.Name, To_String (Stored.Name), Status);
         if Status = OK then MC_Text.Set (Item.Architecture, To_String (Stored.Architecture), Status); end if;
         if Status = OK then MC_Text.Set (Item.Before_Version, To_String (Stored.Before_Version), Status); end if;
         if Status = OK then MC_Text.Set (Item.After_Version, To_String (Stored.After_Version), Status); end if;
         if Status = OK then Item.Kind := Stored.Kind; Item.Before_Original := Stored.Before_Original; Item.After_Original := Stored.After_Original; end if;
      end;
      if Status /= OK then Item := (others => <>); end if;
   exception when others => Item := (others => <>); Status := Indeterminate;
   end Read_Change;
end Pkg_Deb_Transition;
