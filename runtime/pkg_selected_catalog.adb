-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Vectors; with Ada.Containers.Indefinite_Ordered_Maps;
with Ada.Strings.Unbounded; with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_Hex; with MC_Posix; with MC_SHA256; with MC_Text;
with Pkg_Deb_Metadata; with Pkg_Deb_Semantics;
package body Pkg_Selected_Catalog with SPARK_Mode => Off is
   package R renames Pkg_Deb_Relations;
   use Ada.Strings.Unbounded; use type Interfaces.C.unsigned;
   type Stored_Atom is record
      Name, Architecture, Version : Unbounded_String;
      Operator : Pkg_Deb_Semantics.Relation;
      Group_Number : Natural;
   end record;
   type Field_Range is record
      First : Positive := 1;
      Count, Groups : Natural := 0;
   end record;
   type Field_Ranges is array (R.Field_Kind) of Field_Range;
   type Stored_Package is record
      Original, Archive, Control : Digest;
      Name, Version, Architecture, Source_Name, Source_Version : Unbounded_String;
      Multi : Pkg_Deb_Semantics.Multi_Arch;
      Essential, Protected_Package, Has_Installed_Size : Boolean;
      Installed_Size_KiB : Counter;
      Fields : Field_Ranges;
   end record;
   package Atoms is new Ada.Containers.Vectors (Positive, Stored_Atom);
   package Packages is new Ada.Containers.Vectors (Positive, Stored_Package);
   package Positions is new Ada.Containers.Vectors (Positive, Positive);
   package Lookup is new Ada.Containers.Indefinite_Ordered_Maps (String, Positive);
   type Data is record
      Items : Packages.Vector;
      Relations : Atoms.Vector;
      By_Source, By_Identity : Lookup.Map;
      Order : Positions.Vector;
      Text_Bytes : Natural := 0;
      Hash, Payload : Digest := Zero_Digest;
      Complete : Boolean := False;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Catalog) is
   begin Free (Value.State); end Clear;
   overriding procedure Finalize (Value : in out Catalog) is
   begin Clear (Value); end Finalize;
   function Sealed (Value : Catalog) return Boolean is
     (Value.State /= null and then Value.State.Complete);
   function Package_Count (Value : Catalog) return Natural is
     (if Sealed (Value) then Natural (Value.State.Items.Length) else 0);
   function Fingerprint (Value : Catalog) return Digest is
     (if Sealed (Value) then Value.State.Hash else Zero_Digest);
   function Payload_Hash (Value : Catalog) return Digest is
     (if Sealed (Value) then Value.State.Payload else Zero_Digest);
   function Matches_Payload (Value : Catalog; Payload : Pkg_Payload_Index.Index) return Boolean is
     (Sealed (Value) and then Pkg_Payload_Index.Sealed (Payload)
      and then Payload_Hash (Value) = Pkg_Payload_Index.Fingerprint (Payload));
   procedure Time_Left (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Time_Left;
   procedure Add (Value : in out Catalog; Store : in out MC_Store.Store;
                  Original : Digest; Deadline : Counter; Status : out Outcome) is
      type Observation_Access is access Pkg_Deb_Metadata.Observation;
      type Buffer_Access is access Bytes;
      procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Observation_Access);
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      Observed : Observation_Access; Raw : Buffer_Access;
      Used : Natural; Parsed : R.Expression; Atom : R.Atom; Package_Item : Stored_Package;
      procedure Fail is
      begin Free (Observed); Free (Raw); Clear (Value); end Fail;
      procedure Save (Text : MC_Text.Value; Target : out Unbounded_String) is
         Size : constant Natural := MC_Text.Length (Text);
      begin
         if Status /= OK then return; end if;
         if Size > Max_Text_Bytes - Value.State.Text_Bytes then Status := Exhausted; return; end if;
         Target := To_Unbounded_String (MC_Text.Image (Text));
         Value.State.Text_Bytes := Value.State.Text_Bytes + Size;
      end Save;
   begin
      Status := Denied;
      if MC_Posix.Euid = 0 then Fail; return; end if;
      Time_Left (Deadline, Status); if Status /= OK then Fail; return; end if;
      if Original = Zero_Digest or else Sealed (Value) then Status := Invalid_Input; Fail; return; end if;
      if Value.State = null then Value.State := new Data; end if;
      if Value.State.By_Source.Contains (MC_Hex.Encode (Original)) then Status := Conflict; Fail; return; end if;
      if Natural (Value.State.Items.Length) >= Max_Packages then Status := Exhausted; Fail; return; end if;
      Observed := new Pkg_Deb_Metadata.Observation;
      Pkg_Deb_Metadata.Inspect (Store, Original, Deadline, Observed.all, Status);
      if Status /= OK then Fail; return; end if;
      declare
         Key : constant String := MC_Text.Image (Observed.Identity.Name) & ":" & MC_Text.Image (Observed.Identity.Architecture);
      begin
         if Value.State.By_Identity.Contains (Key) then Status := Conflict; Fail; return; end if;
         Value.State.By_Identity.Insert (Key, Natural (Value.State.Items.Length) + 1);
      end;
      Package_Item.Original := Original; Package_Item.Archive := Observed.Archive;
      Package_Item.Control := Observed.Control;
      Save (Observed.Identity.Name, Package_Item.Name);
      Save (Observed.Identity.Version, Package_Item.Version);
      Save (Observed.Identity.Architecture, Package_Item.Architecture);
      Save (Observed.Identity.Source_Name, Package_Item.Source_Name);
      Save (Observed.Identity.Source_Version, Package_Item.Source_Version);
      if Status /= OK then Fail; return; end if;
      Package_Item.Multi := Observed.Identity.Multi;
      Package_Item.Essential := Observed.Identity.Essential;
      Package_Item.Protected_Package := Observed.Identity.Protected_Package;
      Package_Item.Has_Installed_Size := Observed.Identity.Has_Installed_Size;
      Package_Item.Installed_Size_KiB := Observed.Identity.Installed_Size_KiB;
      Raw := new Bytes (1 .. Pkg_Deb_Fields.Max_Control);
      MC_Store.Read_Object (Store, Observed.Control, Raw.all, Used, Status);
      if Status /= OK then Fail; return; end if;
      for Kind in R.Field_Kind loop
         Time_Left (Deadline, Status); if Status /= OK then Fail; return; end if;
         R.Read_Field (Raw (1 .. Used), Observed.Fields, Kind, Parsed, Status);
         if Status /= OK then Fail; return; end if;
         if R.Count (Parsed) > Max_Atoms - Natural (Value.State.Relations.Length) then Status := Exhausted; Fail; return; end if;
         Package_Item.Fields (Kind) := (Natural (Value.State.Relations.Length) + 1, R.Count (Parsed), R.Groups (Parsed));
         for I in 1 .. R.Count (Parsed) loop
            if I mod 64 = 1 then Time_Left (Deadline, Status); if Status /= OK then Fail; return; end if; end if;
            R.Read_Atom (Parsed, I, Atom, Status); if Status /= OK then Fail; return; end if;
            declare Item : Stored_Atom; begin
               Save (Atom.Name, Item.Name); Save (Atom.Architecture, Item.Architecture); Save (Atom.Version, Item.Version);
               if Status /= OK then Fail; return; end if;
               Item.Operator := Atom.Operator; Item.Group_Number := Atom.Group_Number;
               Value.State.Relations.Append (Item);
            end;
         end loop;
      end loop;
      Value.State.Items.Append (Package_Item);
      Value.State.By_Source.Insert (MC_Hex.Encode (Original), Natural (Value.State.Items.Length));
      Free (Observed); Free (Raw);
      Time_Left (Deadline, Status); if Status /= OK then Clear (Value); end if;
   exception
      when Storage_Error => Fail; Status := Exhausted;
      when others => Fail; Status := Indeterminate;
   end Add;
   procedure Seal (Value : in out Catalog; Selected : Selection;
                   Payload : Pkg_Payload_Index.Index; Deadline : Counter;
                   Status : out Outcome) is
      Wanted : Lookup.Map; Source : Pkg_Payload_Index.Package_Source;
      Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      procedure Number (N : Wide) is
         B : Bytes (1 .. 8);
      begin MC_Codec.Put64 (B, 1, N); MC_SHA256.Update (Hash, B); end Number;
      Tag : constant String := "NIACSEL1"; B : Bytes (1 .. Tag'Length);
   begin
      Status := Denied;
      if MC_Posix.Euid = 0 then Clear (Value); return; end if;
      Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
      if Value.State = null or else Selected'Length = 0
        or else not Pkg_Payload_Index.Sealed (Payload) then Status := Invalid_Input; Clear (Value); return; end if;
      if Selected'Length > Max_Packages then Status := Exhausted; Clear (Value); return; end if;
      if Selected'Length /= Natural (Value.State.Items.Length)
        or else Selected'Length /= Pkg_Payload_Index.Package_Count (Payload) then Status := Conflict; Clear (Value); return; end if;
      for I in Selected'Range loop
         Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
         if Selected (I).Original = Zero_Digest or else Selected (I).Control = Zero_Digest then
            Status := Invalid_Input; Clear (Value); return;
         end if;
         declare Key : constant String := MC_Hex.Encode (Selected (I).Original); begin
            if Wanted.Contains (Key) or else not Value.State.By_Source.Contains (Key) then
               Status := Conflict; Clear (Value); return;
            end if;
            if Value.State.Items.Element (Value.State.By_Source.Element (Key)).Control /= Selected (I).Control then
               Status := Conflict; Clear (Value); return;
            end if;
            Wanted.Insert (Key, I);
         end;
      end loop;
      -- Repeated seals revalidate both caller inputs; a previous seal cannot
      -- hide a replaced source set or altered expected control hash.
      Value.State.Order.Clear;
      for I in 1 .. Pkg_Payload_Index.Package_Count (Payload) loop
         Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
         Pkg_Payload_Index.Read_Package (Payload, I, Source, Status);
         if Status /= OK then Clear (Value); return; end if;
         declare Key : constant String := MC_Hex.Encode (Source.Original); begin
            if not Wanted.Contains (Key) then Status := Conflict; Clear (Value); return; end if;
            Value.State.Order.Append (Value.State.By_Source.Element (Key));
         end;
      end loop;
      Number (Tag'Length);
      for I in Tag'Range loop B (I) := Byte (Character'Pos (Tag (I))); end loop;
      MC_SHA256.Update (Hash, B);
      Value.State.Payload := Pkg_Payload_Index.Fingerprint (Payload);
      MC_SHA256.Update (Hash, Value.State.Payload); Number (Wide (Value.State.Items.Length));
      for Position of Value.State.Order loop
         declare Item : constant Stored_Package := Value.State.Items.Element (Position); begin
            MC_SHA256.Update (Hash, Item.Original); MC_SHA256.Update (Hash, Item.Archive); MC_SHA256.Update (Hash, Item.Control);
         end;
      end loop;
      Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
      Value.State.Hash := MC_SHA256.Finish (Hash); Value.State.Complete := True; Status := OK;
   exception
      when Storage_Error => Clear (Value); Status := Exhausted;
      when others => Clear (Value); Status := Indeterminate;
   end Seal;
   procedure Read_Package (Value : Catalog; Position : Positive;
                           Item : out Package_Record; Status : out Outcome) is
      procedure Copy (Source : Unbounded_String; Target : out MC_Text.Value) is
         Result : Outcome;
      begin
         MC_Text.Set (Target, To_String (Source), Result);
         if Result /= OK then Status := Corrupt; end if;
      end Copy;
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position > Package_Count (Value) then return; end if;
      declare Stored : constant Stored_Package := Value.State.Items.Element (Value.State.Order.Element (Position)); begin
         Status := OK;
         Item.Original := Stored.Original; Item.Archive := Stored.Archive; Item.Control := Stored.Control;
         Copy (Stored.Name, Item.Identity.Name); Copy (Stored.Version, Item.Identity.Version);
         Copy (Stored.Architecture, Item.Identity.Architecture); Copy (Stored.Source_Name, Item.Identity.Source_Name);
         Copy (Stored.Source_Version, Item.Identity.Source_Version);
         Item.Identity.Multi := Stored.Multi; Item.Identity.Essential := Stored.Essential;
         Item.Identity.Protected_Package := Stored.Protected_Package;
         Item.Identity.Has_Installed_Size := Stored.Has_Installed_Size; Item.Identity.Installed_Size_KiB := Stored.Installed_Size_KiB;
      end;
      if Status /= OK then Item := (others => <>); end if;
   exception when others => Item := (others => <>); Status := Indeterminate;
   end Read_Package;
   function Atom_Count (Value : Catalog; Position : Positive; Kind : R.Field_Kind) return Natural is
     (if Position > Package_Count (Value) then 0
      else Value.State.Items.Element (Value.State.Order.Element (Position)).Fields (Kind).Count);
   function Group_Count (Value : Catalog; Position : Positive; Kind : R.Field_Kind) return Natural is
     (if Position > Package_Count (Value) then 0
      else Value.State.Items.Element (Value.State.Order.Element (Position)).Fields (Kind).Groups);
   procedure Read_Atom (Value : Catalog; Position : Positive; Kind : R.Field_Kind;
                        Atom_Position : Positive; Item : out R.Atom; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Atom_Position > Atom_Count (Value, Position, Kind) then return; end if;
      declare
         Field : constant Field_Range := Value.State.Items.Element (Value.State.Order.Element (Position)).Fields (Kind);
         Stored : constant Stored_Atom := Value.State.Relations.Element (Field.First + Atom_Position - 1);
      begin
         MC_Text.Set (Item.Name, To_String (Stored.Name), Status);
         if Status = OK then MC_Text.Set (Item.Architecture, To_String (Stored.Architecture), Status); end if;
         if Status = OK then MC_Text.Set (Item.Version, To_String (Stored.Version), Status); end if;
         if Status = OK then Item.Operator := Stored.Operator; Item.Group_Number := Stored.Group_Number; end if;
      end;
      if Status /= OK then Item := (others => <>); end if;
   exception when others => Item := (others => <>); Status := Indeterminate;
   end Read_Atom;
end Pkg_Selected_Catalog;
