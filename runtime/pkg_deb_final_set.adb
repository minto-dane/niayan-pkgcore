-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Vectors; with Ada.Containers.Indefinite_Ordered_Maps;
with Ada.Strings.Unbounded; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_Posix; with MC_SHA256;
with Pkg_Deb_Semantics; with Pkg_Deb_Versions;
package body Pkg_Deb_Final_Set with SPARK_Mode => Off is
   package C renames Pkg_Selected_Catalog; package R renames Pkg_Deb_Relations;
   package S renames Pkg_Deb_Semantics; package V renames Pkg_Deb_Versions;
   use Ada.Strings.Unbounded; use type Interfaces.C.unsigned;
   use type S.Multi_Arch; use type S.Relation; use type V.Ordering; use type R.Field_Kind;
   type Package_Info is record
      Original : Digest;
      Name, Version, Architecture : Unbounded_String;
      Multi : S.Multi_Arch;
   end record;
   type Capability is record
      Owner : Positive;
      Next : Natural := 0;
      Architecture, Version : Unbounded_String;
      Versioned : Boolean := False;
      Virtual : Boolean := False;
   end record;
   package Packages is new Ada.Containers.Vectors (Positive, Package_Info);
   package Capabilities is new Ada.Containers.Vectors (Positive, Capability);
   package Lookup is new Ada.Containers.Indefinite_Ordered_Maps (String, Positive);
   function Passed (Result : Verification) return Boolean is (Result.Complete);
   function Catalog_Hash (Result : Verification) return Digest is (Result.Catalog);
   function Architecture_Hash (Result : Verification) return Digest is (Result.Architectures);
   function Fingerprint (Result : Verification) return Digest is (Result.Hash);
   function Diagnostic (Result : Verification) return Finding is (Result.Issue);
   procedure Number (Hash : in out MC_SHA256.Context; N : Wide) is
      B : Bytes (1 .. 8);
   begin MC_Codec.Put64 (B, 1, N); MC_SHA256.Update (Hash, B); end Number;
   procedure Text (Hash : in out MC_SHA256.Context; Value : String) is
      B : Bytes (1 .. Value'Length);
   begin
      Number (Hash, Wide (Value'Length));
      for I in Value'Range loop B (I - Value'First + 1) := Byte (Character'Pos (Value (I))); end loop;
      MC_SHA256.Update (Hash, B);
   end Text;
   function Architecture_Label (Name : String) return Boolean is
   begin
      if Name'Length not in 1 .. MC_Text.Max_Length or else Name in "all" | "any" | "source" then return False; end if;
      for Ch of Name loop if Ch not in 'a' .. 'z' | '0' .. '9' | '-' then return False; end if; end loop;
      return Name (Name'First) in 'a' .. 'z' | '0' .. '9';
   end Architecture_Label;
   procedure Check (Value : C.Catalog; Native_Architecture : String;
                     Enabled : Architecture_List; Deadline : Counter;
                     Result : out Verification; Status : out Outcome) is
      Items : Packages.Vector; Facts : Capabilities.Vector;
      By_Name, Heads, Architectures : Lookup.Map;
      Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Profile_Hash : Digest; Now : Counter;
      Item : C.Package_Record; Atom : R.Atom;
      Checks : Natural := 0;
      Interrupted : exception;
      procedure Time_Left is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
         if Status /= OK then raise Interrupted; end if;
      end Time_Left;
      procedure Tick is
      begin
         if Checks = 63 then Checks := 0; Time_Left; else Checks := Checks + 1; end if;
      end Tick;
      procedure Reject (Kind : Finding_Kind; Owner : Positive; Other : Natural := 0;
                        Field : R.Field_Kind := R.Depends; Group_Number : Natural := 0;
                        Atom_Position : Natural := 0) is
      begin
         Result := (others => <>);
         Result.Issue := (Kind => Kind, Original => Items.Element (Owner).Original,
            Other_Original => (if Other = 0 then Zero_Digest else Items.Element (Other).Original),
            Field => Field, Group_Number => Group_Number, Atom_Position => Atom_Position);
         Status := (if Kind = Architecture_Not_Enabled then Unsupported else Conflict);
      end Reject;
      procedure Add_Fact (Name : String; Fact : Capability) is
         Saved : Capability := Fact;
      begin
         Tick;
         if Heads.Contains (Name) then Saved.Next := Heads.Element (Name); end if;
         Facts.Append (Saved); Heads.Include (Name, Natural (Facts.Length));
      end Add_Fact;
      function Effective_Architecture (Name : String) return String is
        (if Name = "all" then Native_Architecture else Name);
      function Matches (Owner : Positive; Need : R.Atom; Fact : Capability; Kind : R.Field_Kind) return Boolean is
         Negative : constant Boolean := Kind in R.Conflicts | R.Breaks;
         Provider : constant Package_Info := Items.Element (Fact.Owner);
         Qualifier : constant String := MC_Text.Image (Need.Architecture);
         Wanted : constant String := (if Qualifier'Length > 0 then Qualifier
            elsif Negative then "any" else To_String (Items.Element (Owner).Architecture));
         Arch_OK : Boolean;
         Order : V.Ordering;
      begin
         Tick;
         -- Unpack excludes the self-name set for Conflicts. Configure checks
         -- Breaks against other same-name architecture instances as well.
         if (Kind = R.Conflicts and then Provider.Name = Items.Element (Owner).Name)
           or else (Kind = R.Breaks and then Fact.Owner = Owner) then return False; end if;
         -- The fixed unpack checker does not filter negative virtual matches
         -- by architecture. Their explicit provided version still applies.
         if Negative and then Fact.Virtual then Arch_OK := True;
         elsif Qualifier'Length = 0 and then Provider.Multi = S.Foreign then Arch_OK := True;
         elsif Wanted = "any" and then (Negative or else Provider.Multi = S.Allowed) then Arch_OK := True;
         else Arch_OK := Effective_Architecture (Wanted) = Effective_Architecture (To_String (Fact.Architecture));
         end if;
         if not Arch_OK then return False; end if;
         if Need.Operator = S.Any_Version then return True; end if;
         if not Fact.Versioned then return False; end if;
         Order := V.Compare (To_String (Fact.Version), MC_Text.Image (Need.Version));
         case Need.Operator is
            when S.Any_Version => return True;
            when S.Less_Than => return Order = V.Older;
            when S.At_Most => return Order /= V.Newer;
            when S.Exactly => return Order = V.Equal;
            when S.At_Least => return Order /= V.Older;
            when S.Greater_Than => return Order = V.Newer;
         end case;
      end Matches;
      function Provider_For (Owner : Positive; Need : R.Atom; Kind : R.Field_Kind) return Natural is
         Name : constant String := MC_Text.Image (Need.Name);
         Position : Natural;
      begin
         if not Heads.Contains (Name) then return 0; end if;
         Position := Heads.Element (Name);
         while Position /= 0 loop
            declare Fact : constant Capability := Facts.Element (Position); begin
               if Matches (Owner, Need, Fact, Kind) then return Fact.Owner; end if;
               Position := Fact.Next;
            end;
         end loop;
         return 0;
      end Provider_For;
   begin
      Result := (others => <>); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Time_Left;
      Status := Invalid_Input;
      if not C.Sealed (Value) or else not Architecture_Label (Native_Architecture) or else Enabled'Length = 0 then return; end if;
      if Enabled'Length > Max_Architectures then Status := Exhausted; return; end if;
      for I in Enabled'Range loop
         Tick;
         declare Name : constant String := MC_Text.Image (Enabled (I)); begin
            if not Architecture_Label (Name) or else Architectures.Contains (Name) then Status := Invalid_Input; return; end if;
            Architectures.Insert (Name, I);
         end;
      end loop;
      if not Architectures.Contains (Native_Architecture) then Status := Invalid_Input; return; end if;
      Text (Hash, "NIADARCH1"); Text (Hash, Native_Architecture); Number (Hash, Wide (Enabled'Length));
      for Cursor in Architectures.Iterate loop Text (Hash, Lookup.Key (Cursor)); end loop;
      Profile_Hash := MC_SHA256.Finish (Hash);
      for I in 1 .. C.Package_Count (Value) loop
         Time_Left; C.Read_Package (Value, I, Item, Status); if Status /= OK then return; end if;
         declare
            Name : constant String := MC_Text.Image (Item.Identity.Name);
            Arch : constant String := MC_Text.Image (Item.Identity.Architecture);
            Version : constant String := MC_Text.Image (Item.Identity.Version);
         begin
            Items.Append (Package_Info'(Item.Original, To_Unbounded_String (Name), To_Unbounded_String (Version),
               To_Unbounded_String (Arch), Item.Identity.Multi));
            if Arch /= "all" and then not Architectures.Contains (Arch) then Reject (Architecture_Not_Enabled, I); return; end if;
            if By_Name.Contains (Name) then
               declare First : constant Positive := By_Name.Element (Name); Previous : constant Package_Info := Items.Element (First); begin
                  if Item.Identity.Multi /= S.Same or else Previous.Multi /= S.Same then Reject (Not_Coinstallable, I, First); return; end if;
                  if V.Compare (Version, To_String (Previous.Version)) /= V.Equal then Reject (Version_Skew, I, First); return; end if;
               end;
            else By_Name.Insert (Name, I);
            end if;
         end;
      end loop;
      -- Head insertion in reverse package/Provides order yields deterministic
      -- first-provider diagnostics in ascending canonical source order.
      for I in reverse 1 .. Natural (Items.Length) loop
         Time_Left;
         for J in reverse 1 .. C.Atom_Count (Value, I, R.Provides) loop
            C.Read_Atom (Value, I, R.Provides, J, Atom, Status); if Status /= OK then return; end if;
            Add_Fact (MC_Text.Image (Atom.Name), Capability'(Owner => I, Next => 0,
               Architecture => (if MC_Text.Length (Atom.Architecture) = 0 then Items.Element (I).Architecture
                  else To_Unbounded_String (MC_Text.Image (Atom.Architecture))),
               Version => To_Unbounded_String (MC_Text.Image (Atom.Version)), Versioned => Atom.Operator = S.Exactly, Virtual => True));
         end loop;
         Add_Fact (To_String (Items.Element (I).Name), Capability'(I, 0, Items.Element (I).Architecture, Items.Element (I).Version, True, False));
      end loop;
      for I in 1 .. Natural (Items.Length) loop
         for Kind in R.Field_Kind loop
            if Kind in R.Depends | R.Pre_Depends | R.Conflicts | R.Breaks then
               declare
                  Negative : constant Boolean := Kind in R.Conflicts | R.Breaks;
                  Current_Group, First_Atom : Natural := 0;
                  Satisfied : Boolean := False;
                  Provider : Natural;
               begin
                  for J in 1 .. C.Atom_Count (Value, I, Kind) loop
                     Tick; C.Read_Atom (Value, I, Kind, J, Atom, Status); if Status /= OK then return; end if;
                     if Atom.Group_Number /= Current_Group then
                        if Current_Group /= 0 and then not Negative and then not Satisfied then
                           Reject (Missing_Dependency, I, Field => Kind, Group_Number => Current_Group, Atom_Position => First_Atom); return;
                        end if;
                        Current_Group := Atom.Group_Number; First_Atom := J; Satisfied := False;
                     end if;
                     if Negative or else not Satisfied then
                        Provider := Provider_For (I, Atom, Kind);
                        if Negative and then Provider /= 0 then
                           Reject (Present_Conflict, I, Provider, Kind, Current_Group, J); return;
                        end if;
                        Satisfied := Provider /= 0;
                     end if;
                  end loop;
                  if Current_Group /= 0 and then not Negative and then not Satisfied then
                     Reject (Missing_Dependency, I, Field => Kind, Group_Number => Current_Group, Atom_Position => First_Atom); return;
                  end if;
               end;
            end if;
         end loop;
      end loop;
      Time_Left;
      Hash := MC_SHA256.Initialize; Text (Hash, "NIADFINAL1");
      MC_SHA256.Update (Hash, C.Fingerprint (Value)); MC_SHA256.Update (Hash, Profile_Hash);
      Result := (True, C.Fingerprint (Value), Profile_Hash, MC_SHA256.Finish (Hash), (Kind => No_Violation, others => <>)); Status := OK;
   exception
      when Interrupted => Result := (others => <>);
      when Storage_Error => Result := (others => <>); Status := Exhausted;
      when others => Result := (others => <>); Status := Indeterminate;
   end Check;
end Pkg_Deb_Final_Set;
