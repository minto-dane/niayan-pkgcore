-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Ordered_Maps; with Ada.Strings.Unbounded; with Ada.Unchecked_Deallocation;
with Interfaces.C; with MC_Clock; with MC_Codec; with MC_Posix; with MC_SHA256; with MC_Text;
with Pkg_Deb_Payload; with Pkg_Deb_Relations; with Pkg_Deb_Semantics; with Pkg_Deb_Versions;
package body Pkg_Payload_Ownership with SPARK_Mode => Off is
   package C renames Pkg_Selected_Catalog; package X renames Pkg_Payload_Index;
   package P renames Pkg_Deb_Payload; package R renames Pkg_Deb_Relations;
   package S renames Pkg_Deb_Semantics; package V renames Pkg_Deb_Versions;
   use Ada.Strings.Unbounded; use type Interfaces.C.unsigned; use type P.Entry_Kind;
   use type S.Multi_Arch; use type S.Relation; use type P.Byte_Strings.Bounded_String; use type V.Ordering; use type Word; use type Wide;
   function Security_Equal (A, B : P.Attributes) return Boolean is
     (A.Mode = B.Mode and then A.UID = B.UID and then A.GID = B.GID and then
      A.Xattrs = B.Xattrs and then A.ACLs = B.ACLs and then A.Flags_Set = B.Flags_Set and then A.Flags_Clear = B.Flags_Clear);
   procedure Check (Catalog : C.Catalog; Payload : X.Index; Chosen : Pkg_Root_Archive.Selection;
      Native_Architecture : String; Deadline : Counter; Binding : out Digest; Issue : out Finding; Status : out Outcome) is
      type Package_Info is record
         Original : Digest; Name, Version, Architecture : Unbounded_String; Multi : S.Multi_Arch;
      end record;
      type Packages is array (Positive range <>) of Package_Info;
      type Packages_Access is access Packages;
      procedure Free is new Ada.Unchecked_Deallocation (Packages, Packages_Access);
      Items : Packages_Access := null;
      package Decisions is new Ada.Containers.Ordered_Maps (Natural, Boolean);
      Replacements : Decisions.Map;
      Selected, Other, Selected_Inode, Other_Inode : X.Claim;
      State : X.Path_State; Item : C.Package_Record; Atom : R.Atom;
      Cursor : Positive := 1; Owner, Loser : Natural; Pick : Positive;
      Now : Counter; Hash : MC_SHA256.Context := MC_SHA256.Initialize; Word_Bytes : Bytes (1 .. 8);
      Interrupted : exception;
      procedure Good is
      begin if Status /= OK then raise Interrupted; end if; end Good;
      procedure Tick is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status); Good;
         if Now >= Deadline then Status := Stale; Good; end if;
      end Tick;
      procedure Reject (Kind : Failure_Kind; Other_Position : Natural := 0) is
      begin Issue := (Kind, Pick, Other_Position); Status := Conflict; raise Interrupted; end Reject;
      procedure Number (N : Natural) is
      begin MC_Codec.Put64 (Word_Bytes, 1, Wide (N)); MC_SHA256.Update (Hash, Word_Bytes); end Number;
      function Package_Position (Original : Digest) return Natural is
         First : Positive := 1; Last : Positive := Items'Last + 1; Middle : Positive;
      begin
         while First < Last loop
            Middle := First + (Last - First) / 2;
            if Items (Middle).Original < Original then First := Middle + 1; else Last := Middle; end if;
         end loop;
         return (if First <= Items'Last and then Items (First).Original = Original then First else 0);
      end Package_Position;
      function Replaces (Winner, Victim : Positive) return Boolean is
         Key : constant Natural := (Winner - 1) * C.Max_Packages + Victim - 1;
         Allowed : Boolean := False; Order : V.Ordering;
      begin
         if Replacements.Contains (Key) then return Replacements.Element (Key); end if;
         for I in 1 .. C.Atom_Count (Catalog, Winner, R.Replaces) loop
            Tick; C.Read_Atom (Catalog, Winner, R.Replaces, I, Atom, Status); Good;
            if MC_Text.Image (Atom.Name) = To_String (Items (Victim).Name) then
               declare Qualifier : constant String := MC_Text.Image (Atom.Architecture);
                  Victim_Arch : constant String := To_String (Items (Victim).Architecture);
                  function Effective (Name : String) return String is (if Name = "all" then Native_Architecture else Name);
               begin
                  Allowed := Qualifier in "" | "any" or else Effective (Qualifier) = Effective (Victim_Arch);
               end;
               if Allowed and then Atom.Operator /= S.Any_Version then
                  Order := V.Compare (To_String (Items (Victim).Version), MC_Text.Image (Atom.Version));
                  case Atom.Operator is
                     when S.Any_Version => null;
                     when S.Less_Than => Allowed := Order = V.Older;
                     when S.At_Most => Allowed := Order /= V.Newer;
                     when S.Exactly => Allowed := Order = V.Equal;
                     when S.At_Least => Allowed := Order /= V.Older;
                     when S.Greater_Than => Allowed := Order = V.Newer;
                  end case;
               end if;
               exit when Allowed;
            end if;
         end loop;
         -- Bound the per-call memo independently of the number of path pairs.
         if Natural (Replacements.Length) < X.Max_Claims then Replacements.Insert (Key, Allowed); end if;
         return Allowed;
      end Replaces;
      function Same_Instance_Set return Boolean is
        (Items (Owner).Name = Items (Loser).Name and then Items (Owner).Multi = S.Same and then
         Items (Loser).Multi = S.Same and then Items (Owner).Architecture /= Items (Loser).Architecture and then
         V.Compare (To_String (Items (Owner).Version), To_String (Items (Loser).Version)) = V.Equal);
   begin
      Binding := Zero_Digest; Issue := (others => <>); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Deadline = Counter'Last or else not C.Matches_Payload (Catalog, Payload) or else
        Chosen'Length /= X.Path_Count (Payload) or else Chosen'Length = 0 or else
        Native_Architecture'Length not in 1 .. MC_Text.Max_Length or else Native_Architecture in "all" | "any" | "source" then return; end if;
      for Ch of Native_Architecture loop if Ch not in 'a' .. 'z' | '0' .. '9' | '-' then return; end if; end loop;
      if Native_Architecture (Native_Architecture'First) not in 'a' .. 'z' | '0' .. '9' then return; end if;
      Tick; Items := new Packages (1 .. C.Package_Count (Catalog));
      for I in Items'Range loop
         Tick; C.Read_Package (Catalog, I, Item, Status); Good;
         Items (I) := (Item.Original, To_Unbounded_String (MC_Text.Image (Item.Identity.Name)),
            To_Unbounded_String (MC_Text.Image (Item.Identity.Version)),
            To_Unbounded_String (MC_Text.Image (Item.Identity.Architecture)), Item.Identity.Multi);
      end loop;
      MC_SHA256.Update (Hash, Bytes'(78, 73, 65, 80, 79, 87, 78, 49));
      MC_SHA256.Update (Hash, C.Fingerprint (Catalog)); MC_SHA256.Update (Hash, X.Fingerprint (Payload));
      Number (Native_Architecture'Length);
      for Ch of Native_Architecture loop MC_SHA256.Update (Hash, Bytes'(1 => Byte (Character'Pos (Ch)))); end loop;
      Number (Chosen'Length);
      for Offset in 0 .. Chosen'Length - 1 loop
         Tick; Pick := Chosen (Chosen'First + Offset);
         X.Read_Claim (Payload, Pick, Selected, Status); Good;
         X.Inspect_Path (Payload, P.Byte_Strings.To_String (Selected.Item.Path), State, Status); Good;
         if State.First /= Cursor or else Pick not in State.First .. State.Last then Reject (Invalid_Selection); end if;
         Owner := Package_Position (Selected.Source.Original); if Owner = 0 then Status := Corrupt; Good; end if;
         X.Read_Inode (Payload, Pick, Selected_Inode, Status); Good;
         for J in State.First .. State.Last loop
            Tick;
            if J /= Pick then
               X.Read_Claim (Payload, J, Other, Status); Good;
               Loser := Package_Position (Other.Source.Original); if Loser = 0 then Status := Corrupt; Good; end if;
               if Selected.Item.Values.Kind = P.Directory and then Other.Item.Values.Kind = P.Directory and then
                 Security_Equal (Selected.Item.Values, Other.Item.Values) then null;
               elsif Same_Instance_Set then
                  X.Read_Inode (Payload, J, Other_Inode, Status); Good;
                  if Selected_Inode.Item.Values.Kind /= Other_Inode.Item.Values.Kind or else
                    not Security_Equal (Selected_Inode.Item.Values, Other_Inode.Item.Values) or else
                    Selected_Inode.Item.Values.Content /= Other_Inode.Item.Values.Content or else
                    Selected_Inode.Item.Values.Content_Size /= Other_Inode.Item.Values.Content_Size or else
                    Selected_Inode.Item.Link_Target /= Other_Inode.Item.Link_Target or else
                    Selected_Inode.Item.Values.Device_Major /= Other_Inode.Item.Values.Device_Major or else
                    Selected_Inode.Item.Values.Device_Minor /= Other_Inode.Item.Values.Device_Minor then
                     Reject (Different_Shared_File, J);
                  end if;
               elsif not Replaces (Owner, Loser) then
                  Reject ((if Selected.Item.Values.Kind = P.Directory and then Other.Item.Values.Kind = P.Directory
                     then Directory_Attributes else Unjustified_Takeover), J);
               end if;
            end if;
         end loop;
         Number (Pick); Cursor := State.Last + 1;
      end loop;
      Tick; if Cursor /= X.Claim_Count (Payload) + 1 then Reject (Invalid_Selection); end if;
      Binding := MC_SHA256.Finish (Hash); Issue := (Kind => None, others => <>); Status := OK; Free (Items);
   exception
      when Interrupted => Binding := Zero_Digest; Free (Items);
      when Storage_Error => Binding := Zero_Digest; Free (Items); Status := Exhausted;
      when others => Binding := Zero_Digest; Free (Items); Status := Indeterminate;
   end Check;
end Pkg_Payload_Ownership;
