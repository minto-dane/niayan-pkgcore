-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Vectors; with Ada.Containers.Indefinite_Ordered_Maps;
with Ada.Strings.Unbounded; with Ada.Unchecked_Deallocation;
with Interfaces; with Interfaces.C; with MC_Clock; with MC_Codec; with MC_Hex; with MC_Posix; with MC_SHA256;
package body Pkg_Payload_Index with SPARK_Mode => Off is
   package P renames Pkg_Deb_Payload;
   use Ada.Strings.Unbounded;
   use type P.Entry_Kind; use type P.Attributes; use type Interfaces.C.unsigned;
   type Stored_Claim is record
      Owner, Position : Positive;
      Path, Link_Target, User_Name, Group_Name : Unbounded_String;
      Values : P.Attributes;
   end record;
   type Stored_Package is record
      Source : Package_Source;
      First : Positive;
   end record;
   package Claims is new Ada.Containers.Vectors (Positive, Stored_Claim);
   package Packages is new Ada.Containers.Vectors (Positive, Stored_Package);
   package Positions is new Ada.Containers.Vectors (Positive, Positive);
   package Sources is new Ada.Containers.Indefinite_Ordered_Maps (String, Positive);
   type Data is record
      Items : Claims.Vector;
      Owners : Packages.Vector;
      By_Source : Sources.Map;
      Claim_Order, Owner_Order : Positions.Vector;
      Names, Paths : Natural := 0;
      Hash : Digest := Zero_Digest;
      Complete : Boolean := False;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Index) is
   begin Free (Value.State); end Clear;
   overriding procedure Finalize (Value : in out Index) is
   begin Clear (Value); end Finalize;
   function Sealed (Value : Index) return Boolean is
     (Value.State /= null and then Value.State.Complete);
   function Package_Count (Value : Index) return Natural is
     (if Sealed (Value) then Natural (Value.State.Owners.Length) else 0);
   function Claim_Count (Value : Index) return Natural is
     (if Sealed (Value) then Natural (Value.State.Items.Length) else 0);
   function Path_Count (Value : Index) return Natural is
     (if Sealed (Value) then Value.State.Paths else 0);
   function Fingerprint (Value : Index) return Digest is
     (if Sealed (Value) then Value.State.Hash else Zero_Digest);
   procedure Time_Left (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Time_Left;
   procedure Add (Value : in out Index; Payload : P.Inventory;
                  Deadline : Counter; Status : out Outcome) is
      Original : constant Digest := P.Original_Hash (Payload);
      Tar : constant Digest := P.Tar_Hash (Payload);
      Count : constant Natural := P.Count (Payload);
      Owner : Positive; Item : P.Payload_Entry;
   begin
      Status := Denied;
      if MC_Posix.Euid = 0 then Clear (Value); return; end if;
      Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
      if Original = Zero_Digest or else Tar = Zero_Digest or else Sealed (Value) then
         Clear (Value); Status := Invalid_Input; return;
      end if;
      if Value.State = null then Value.State := new Data; end if;
      if Value.State.By_Source.Contains (MC_Hex.Encode (Original)) then
         Clear (Value); Status := Conflict; return;
      end if;
      if Natural (Value.State.Owners.Length) >= Max_Packages
        or else Count > Max_Claims - Natural (Value.State.Items.Length) then
         Clear (Value); Status := Exhausted; return;
      end if;
      Owner := Natural (Value.State.Owners.Length) + 1;
      Value.State.Owners.Append (Stored_Package'((Original, Tar, Count), Natural (Value.State.Items.Length) + 1));
      Value.State.By_Source.Insert (MC_Hex.Encode (Original), Owner);
      for I in 1 .. Count loop
         if I mod 64 = 1 then
            Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
         end if;
         P.Read_Entry (Payload, I, Item, Status);
         if Status /= OK then Clear (Value); return; end if;
         declare
            Path : constant String := P.Byte_Strings.To_String (Item.Path);
            Link : constant String := P.Byte_Strings.To_String (Item.Link_Target);
            User : constant String := P.Byte_Strings.To_String (Item.User_Name);
            Group : constant String := P.Byte_Strings.To_String (Item.Group_Name);
            Size : constant Natural := Path'Length + Link'Length + User'Length + Group'Length;
         begin
            if Size > Max_Name_Bytes - Value.State.Names then
               Clear (Value); Status := Exhausted; return;
            end if;
            Value.State.Items.Append (Stored_Claim'(Owner, I,
               To_Unbounded_String (Path), To_Unbounded_String (Link),
               To_Unbounded_String (User), To_Unbounded_String (Group), Item.Values));
            Value.State.Names := Value.State.Names + Size;
         end;
      end loop;
      Time_Left (Deadline, Status); if Status /= OK then Clear (Value); end if;
   exception
      when Storage_Error => Clear (Value); Status := Exhausted;
      when others => Clear (Value); Status := Indeterminate;
   end Add;
   function Inode_Position (Value : Index; Stored_Position : Positive) return Positive is
      E : constant Stored_Claim := Value.State.Items.Element (Stored_Position);
   begin
      if E.Values.Kind = P.Hard_Link then
         return Value.State.Owners.Element (E.Owner).First + E.Values.Inode_Entry - 1;
      end if;
      return Stored_Position;
   end Inode_Position;
   procedure Expand (Value : Index; Position : Positive; Item : out Claim) is
      E : constant Stored_Claim := Value.State.Items.Element (Position);
   begin
      Item := (Source => Value.State.Owners.Element (E.Owner).Source,
               Source_Position => E.Position, Item => (others => <>));
      Item.Item.Path := P.Byte_Strings.To_Bounded_String (To_String (E.Path));
      Item.Item.Link_Target := P.Byte_Strings.To_Bounded_String (To_String (E.Link_Target));
      Item.Item.User_Name := P.Byte_Strings.To_Bounded_String (To_String (E.User_Name));
      Item.Item.Group_Name := P.Byte_Strings.To_Bounded_String (To_String (E.Group_Name));
      Item.Item.Values := E.Values;
   end Expand;
   procedure Read_Package (Value : Index; Position : Positive;
                           Source : out Package_Source; Status : out Outcome) is
   begin
      Source := (others => <>); Status := Invalid_Input;
      if Position > Package_Count (Value) then return; end if;
      Source := Value.State.Owners.Element (Value.State.Owner_Order.Element (Position)).Source;
      Status := OK;
   end Read_Package;
   procedure Read_Claim (Value : Index; Position : Positive;
                         Item : out Claim; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position > Claim_Count (Value) then return; end if;
      Expand (Value, Value.State.Claim_Order.Element (Position), Item); Status := OK;
   end Read_Claim;
   procedure Read_Inode (Value : Index; Position : Positive;
                         Item : out Claim; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position > Claim_Count (Value) then return; end if;
      Expand (Value, Inode_Position (Value, Value.State.Claim_Order.Element (Position)), Item); Status := OK;
   end Read_Inode;
   procedure Seal (Value : in out Index; Deadline : Counter; Status : out Outcome) is
      Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Previous : Unbounded_String;
      Sort_Checks : Natural range 0 .. 1023 := 0;
      Sort_Expired : exception;
      function Less (Left, Right : Positive) return Boolean is
         L : constant Stored_Claim := Value.State.Items.Element (Left);
         R : constant Stored_Claim := Value.State.Items.Element (Right);
      begin
         if Sort_Checks = 1023 then
            Sort_Checks := 0; Time_Left (Deadline, Status);
            if Status /= OK then raise Sort_Expired; end if;
         else Sort_Checks := Sort_Checks + 1; end if;
         if L.Path /= R.Path then return L.Path < R.Path; end if;
         return MC_Hex.Encode (Value.State.Owners.Element (L.Owner).Source.Original)
              < MC_Hex.Encode (Value.State.Owners.Element (R.Owner).Source.Original);
      end Less;
      package Sorter is new Positions.Generic_Sorting (Less);
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
      procedure Clock (T : P.Timestamp) is
      begin
         Number (Boolean'Pos (T.Present)); Number (Wide'Mod (T.Seconds)); Number (Wide (T.Nanoseconds));
      end Clock;
   begin
      Status := Denied;
      if MC_Posix.Euid = 0 then Clear (Value); return; end if;
      Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
      if Value.State = null then Status := Invalid_Input; return; end if;
      if Value.State.Complete then Status := OK; return; end if;
      for Cursor in Value.State.By_Source.Iterate loop
         Value.State.Owner_Order.Append (Sources.Element (Cursor));
      end loop;
      for I in 1 .. Natural (Value.State.Items.Length) loop Value.State.Claim_Order.Append (I); end loop;
      Sorter.Sort (Value.State.Claim_Order);
      Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
      Text ("NIAPIDX1"); Number (Wide (Value.State.Owners.Length)); Number (Wide (Value.State.Items.Length));
      for O of Value.State.Owner_Order loop
         declare S : constant Package_Source := Value.State.Owners.Element (O).Source; begin
            MC_SHA256.Update (Hash, S.Original); MC_SHA256.Update (Hash, S.Tar); Number (Wide (S.Entries));
         end;
      end loop;
      for I in 1 .. Natural (Value.State.Claim_Order.Length) loop
         if I mod 64 = 1 then
            Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
         end if;
         declare
            E : constant Stored_Claim := Value.State.Items.Element (Value.State.Claim_Order.Element (I));
            A : constant P.Attributes := E.Values;
            Owner : constant Stored_Package := Value.State.Owners.Element (E.Owner);
         begin
            if I = 1 or else E.Path /= Previous then Value.State.Paths := Value.State.Paths + 1; end if;
            Previous := E.Path;
            if A.Kind = P.Hard_Link then
               if A.Inode_Entry = 0 or else A.Inode_Entry > Owner.Source.Entries
                 or else Value.State.Items.Element (Owner.First + A.Inode_Entry - 1).Values.Kind /= P.Regular then
                  Clear (Value); Status := Corrupt; return;
               end if;
            end if;
            Text (To_String (E.Path)); MC_SHA256.Update (Hash, Owner.Source.Original); Number (Wide (E.Position));
            Text (To_String (E.Link_Target)); Text (To_String (E.User_Name)); Text (To_String (E.Group_Name));
            Number (P.Entry_Kind'Pos (A.Kind)); Number (Wide (A.Mode)); Number (Wide (A.UID)); Number (Wide (A.GID));
            Number (Wide (A.Device_Major)); Number (Wide (A.Device_Minor));
            Clock (A.Modified); Clock (A.Accessed); Clock (A.Changed); Clock (A.Created);
            Number (Wide (A.Archive_Size)); Number (Wide (A.Content_Size));
            MC_SHA256.Update (Hash, A.Content); MC_SHA256.Update (Hash, A.Xattrs); MC_SHA256.Update (Hash, A.ACLs);
            Number (A.Flags_Set); Number (A.Flags_Clear); Number (Wide (A.Inode_Entry));
         end;
      end loop;
      Time_Left (Deadline, Status); if Status /= OK then Clear (Value); return; end if;
      Value.State.Hash := MC_SHA256.Finish (Hash); Value.State.Complete := True; Status := OK;
   exception
      when Sort_Expired => Clear (Value);
      when Storage_Error => Clear (Value); Status := Exhausted;
      when others => Clear (Value); Status := Indeterminate;
   end Seal;
   procedure Inspect_Path (Value : Index; Path : String;
                           State : out Path_State; Status : out Outcome) is
      function Path_At (Position : Positive) return String is
        (To_String (Value.State.Items.Element (Value.State.Claim_Order.Element (Position)).Path));
      function Lower (Name : String; After : Boolean := False) return Positive is
         First : Positive := 1; Last : Positive := Claim_Count (Value) + 1; Middle : Positive;
      begin
         while First < Last loop
            Middle := First + (Last - First) / 2;
            if Path_At (Middle) < Name or else (After and then Path_At (Middle) = Name) then First := Middle + 1;
            else Last := Middle; end if;
         end loop;
         return First;
      end Lower;
      function Directory_Only (First, Last : Natural) return Boolean is
      begin
         for I in First .. Last loop
            if Value.State.Items.Element (Value.State.Claim_Order.Element (I)).Values.Kind /= P.Directory then return False; end if;
         end loop;
         return True;
      end Directory_Only;
      procedure Ancestor (Name : String; Direct : Boolean) is
         First : constant Positive := Lower (Name); Last : constant Natural := Lower (Name, True) - 1;
      begin
         if First > Last then
            if Direct then State.Parent_Missing := True; end if;
         elsif not Directory_Only (First, Last) then State.Non_Directory_Ancestor := True;
         end if;
      end Ancestor;
      First, Last : Natural;
   begin
      State := (others => <>); Status := Invalid_Input;
      if not Sealed (Value) or else Path'Length > P.Max_Name then return; end if;
      First := Lower (Path); Last := Lower (Path, True) - 1;
      if First > Last then Status := OK; return; end if;
      State.First := First; State.Last := Last;
      State.All_Directories := Directory_Only (First, Last); State.Same_Inode_Attributes := True;
      declare
         Base : constant Stored_Claim := Value.State.Items.Element (Inode_Position (Value, Value.State.Claim_Order.Element (First)));
         Expected : P.Attributes := Base.Values;
      begin
         Expected.Inode_Entry := 0;
         for I in First + 1 .. Last loop
            declare
               E : constant Stored_Claim := Value.State.Items.Element (Inode_Position (Value, Value.State.Claim_Order.Element (I)));
               A : P.Attributes := E.Values;
            begin
               A.Inode_Entry := 0;
               if A /= Expected or else E.Link_Target /= Base.Link_Target then State.Same_Inode_Attributes := False; end if;
            end;
         end loop;
      end;
      if Path'Length > 0 then
         declare Last_Slash : Natural := 0; begin
            for I in reverse Path'Range loop if Path (I) = '/' then Last_Slash := I; exit; end if; end loop;
            Ancestor ("", Last_Slash = 0);
            for I in Path'Range loop
               if Path (I) = '/' then Ancestor (Path (Path'First .. I - 1), I = Last_Slash); end if;
            end loop;
         end;
      end if;
      Status := OK;
   exception when others => State := (others => <>); Status := Indeterminate;
   end Inspect_Path;
end Pkg_Payload_Index;
