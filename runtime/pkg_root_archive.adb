-- SPDX-License-Identifier: MIT
with Ada.Containers.Vectors; with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix; with MC_SHA256;
with Pkg_Catalog_Retention; with Pkg_Catalog_Store; with Pkg_Deb_Payload;
with Pkg_Selected_Catalog; with Pkg_Tar_Framing;
package body Pkg_Root_Archive with SPARK_Mode => Off is
   package X renames Pkg_Payload_Index; package P renames Pkg_Deb_Payload;
   package T renames Pkg_Tar_Framing;
   use type Interfaces.C.unsigned; use type Wide; use type MC_FS.Entry_Info; use type P.Entry_Kind;
   Magic : constant Bytes := (78, 73, 65, 82, 79, 79, 84, 49);
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   procedure Tick (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      Status := Invalid_Input; if Deadline = Counter'Last then return; end if;
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Tick;
   function Padded (Size : Counter) return Counter is
     (Size + (if Size mod 512 = 0 then 0 else 512 - Size mod 512));
   procedure Build (Store : in out MC_Store.Store; Catalog, Closure : Digest;
      Chosen : Selection; Limit, Deadline : Counter;
      Manifest, Archive : out Digest; Status : out Outcome) is
      type Part is record
         Claim, Source_Number, Ordinal, Dependency : Natural := 0;
         First, Length : Counter := 0;
         Directory, Done, Visiting : Boolean := False;
      end record;
      type Part_Array is array (Positive range <>) of Part;
      type Part_Access is access Part_Array;
      procedure Free is new Ada.Unchecked_Deallocation (Part_Array, Part_Access);
      type Source_Info is record
         Source : X.Package_Source;
         Stat : MC_FS.Entry_Info;
      end record;
      type Source_Array is array (Positive range <>) of Source_Info;
      type Source_Access is access Source_Array;
      procedure Free is new Ada.Unchecked_Deallocation (Source_Array, Source_Access);
      package Positions is new Ada.Containers.Vectors (Positive, Positive);
      Value : Pkg_Selected_Catalog.Catalog; Payload : X.Index;
      Parts : Part_Access := null; Sources : Source_Access := null;
      By_Source, Order, Stack : Positions.Vector;
      File : MC_FS.File; Writer : MC_Store.Writer; Frames : T.Index;
      Current_Source : Natural := 0; Total : Counter := 1_024;
      Expected, Root_Hash, Saved : Digest := Zero_Digest;
      Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Buffer : Bytes (1 .. 65_536); Wire : Buffer_Access := null;
      Sort_Count : Natural := 0;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Clock is
      begin Tick (Deadline, Status); Check; end Clock;
      procedure Cleanup is
      begin MC_FS.Close (File); MC_Store.Abort_Write (Writer); Free (Parts); Free (Sources); Free (Wire); end Cleanup;
      function Path_At (Position : Positive) return String is
         Item : X.Claim;
      begin
         X.Read_Claim (Payload, Parts (Position).Claim, Item, Status); Check;
         return P.Byte_Strings.To_String (Item.Item.Path);
      end Path_At;
      function Selected (Name : String) return Natural is
         First : Positive := 1; Last : Positive := Chosen'Length + 1; Middle : Positive;
      begin
         while First < Last loop
            Clock; Middle := First + (Last - First) / 2;
            if Path_At (Middle) < Name then First := Middle + 1; else Last := Middle; end if;
         end loop;
         return (if First <= Chosen'Length and then Path_At (First) = Name then First else 0);
      end Selected;
      function Source_Number (Original : Digest) return Natural is
         First : Positive := 1; Last : Positive := Sources'Last + 1; Middle : Positive;
      begin
         while First < Last loop
            Middle := First + (Last - First) / 2;
            if Sources (Middle).Source.Original < Original then First := Middle + 1; else Last := Middle; end if;
         end loop;
         return (if First <= Sources'Last and then Sources (First).Source.Original = Original then First else 0);
      end Source_Number;
      function Less (Left, Right : Positive) return Boolean is
      begin
         Sort_Count := Sort_Count + 1;
         if Sort_Count = 1_024 then Clock; Sort_Count := 0; end if;
         return Parts (Left).Source_Number < Parts (Right).Source_Number or else
           (Parts (Left).Source_Number = Parts (Right).Source_Number and then Parts (Left).Ordinal < Parts (Right).Ordinal);
      end Less;
      package Sorting is new Positions.Generic_Sorting (Less);
      procedure Close_Source is
         After : MC_FS.Entry_Info;
      begin
         if Current_Source = 0 then return; end if;
         MC_FS.Info (File, After, Status); Check;
         if After /= Sources (Current_Source).Stat then Status := Stale; Check; end if;
         MC_FS.Close (File); Current_Source := 0; Clock;
      end Close_Source;
      procedure Open_Source (Number : Positive; Remember : Boolean := False) is
         Info : MC_FS.Entry_Info;
      begin
         if Current_Source = Number then return; end if;
         Close_Source; Clock;
         MC_Store.Open_Object (Store, Sources (Number).Source.Tar, File, Status); Check;
         MC_FS.Info (File, Info, Status); Check;
         if Remember then Sources (Number).Stat := Info;
         elsif Sources (Number).Stat /= Info then Status := Stale; Check; end if;
         Current_Source := Number; Clock;
      end Open_Source;
      procedure Emit (Position : Positive) is
         At_Byte : Counter := 0; Used, Take : Natural;
      begin
         Open_Source (Parts (Position).Source_Number);
         while At_Byte < Parts (Position).Length loop
            Clock; Take := Natural (Counter'Min (Buffer'Length, Parts (Position).Length - At_Byte));
            MC_FS.Read_At (File, Parts (Position).First + At_Byte, Buffer (1 .. Take), Used, Status); Check;
            if Used /= Take then Status := Corrupt; Check; end if;
            if Expected = Zero_Digest then MC_SHA256.Update (Hash, Buffer (1 .. Used));
            else MC_Store.Write_Chunk (Writer, Buffer (1 .. Used), Status); Check; end if;
            At_Byte := At_Byte + Counter (Used);
         end loop;
      end Emit;
   begin
      Manifest := Zero_Digest; Archive := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Catalog = Zero_Digest or else Closure = Zero_Digest or else Chosen'Length not in 1 .. Max_Entries
        or else Limit not in 1_024 .. MC_Store.Max_Object_Size then return; end if;
      Clock;
      -- Retained inputs must exist before a native reader can reconstruct them.
      Pkg_Catalog_Retention.Verify (Store, Catalog, Closure, Deadline, Status); Check;
      Pkg_Catalog_Store.Load (Store, Catalog, Deadline, Value, Payload, Status); Check;
      if Chosen'Length /= X.Path_Count (Payload) then Status := Conflict; Check; end if;
      Parts := new Part_Array (1 .. Chosen'Length);
      Sources := new Source_Array (1 .. X.Package_Count (Payload));
      for I in Sources'Range loop
         Clock; X.Read_Package (Payload, I, Sources (I).Source, Status); Check;
      end loop;
      declare Cursor : Positive := 1; Item : X.Claim; State : X.Path_State; begin
         for I in Parts'Range loop
            Clock; Parts (I).Claim := Chosen (Chosen'First + (I - 1));
            X.Read_Claim (Payload, Parts (I).Claim, Item, Status); Check;
            X.Inspect_Path (Payload, P.Byte_Strings.To_String (Item.Item.Path), State, Status); Check;
            if State.First /= Cursor or else Parts (I).Claim not in State.First .. State.Last then
               Status := Conflict; Check;
            end if;
            Cursor := State.Last + 1;
            Parts (I).Source_Number := Source_Number (Item.Source.Original);
            if Parts (I).Source_Number = 0 or else Item.Source.Tar /= Sources (Parts (I).Source_Number).Source.Tar
              or else Item.Source_Position not in 1 .. Item.Source.Entries then Status := Corrupt; Check; end if;
            Parts (I).Ordinal := Item.Source_Position; Parts (I).Directory := Item.Item.Values.Kind = P.Directory;
            By_Source.Append (I);
         end loop;
         if Cursor /= X.Claim_Count (Payload) + 1 or else Path_At (1) /= "" or else not Parts (1).Directory then
            Status := Conflict; Check;
         end if;
      end;
      for I in Parts'Range loop
         Clock;
         declare Name : constant String := Path_At (I); Parent : Natural; Item : X.Claim; begin
            for At_Char in Name'Range loop
               if Name (At_Char) = '/' then
                  Parent := Selected (Name (Name'First .. At_Char - 1));
                  if Parent = 0 or else not Parts (Parent).Directory then Status := Conflict; Check; end if;
               end if;
            end loop;
            X.Read_Claim (Payload, Parts (I).Claim, Item, Status); Check;
            if Item.Item.Values.Kind = P.Hard_Link then
               Parts (I).Dependency := Selected (P.Byte_Strings.To_String (Item.Item.Link_Target));
               if Parts (I).Dependency = 0 or else Parts (Parts (I).Dependency).Source_Number /= Parts (I).Source_Number then
                  Status := Conflict; Check;
               end if;
            end if;
         end;
      end loop;
      Sorting.Sort (By_Source); Clock;
      for Position of By_Source loop
         Clock;
         if Current_Source /= Parts (Position).Source_Number then
            Open_Source (Parts (Position).Source_Number, Remember => True);
            T.Scan (File, Sources (Current_Source).Stat.Size, Deadline, Frames, Status); Check;
            if T.Count (Frames) /= Sources (Current_Source).Source.Entries then Status := Corrupt; Check; end if;
         end if;
         declare F : constant T.Frame := T.At_Index (Frames, Parts (Position).Ordinal); begin
            if Parts (Position).Ordinal = 1 then Parts (Position).First := 0;
            else
               declare Previous : constant T.Frame := T.At_Index (Frames, Parts (Position).Ordinal - 1); begin
                  Parts (Position).First := Previous.Body_Start + Padded (Previous.Size);
               end;
            end if;
            if F.Body_Start + Padded (F.Size) <= Parts (Position).First then Status := Corrupt; Check; end if;
            Parts (Position).Length := F.Body_Start + Padded (F.Size) - Parts (Position).First;
            if Parts (Position).Length > Limit - Total then Status := Exhausted; Check; end if;
            Total := Total + Parts (Position).Length;
         end;
      end loop;
      Close_Source;
      for Position of By_Source loop
         if Parts (Position).Directory then Order.Append (Position); Parts (Position).Done := True; end if;
      end loop;
      for Position of By_Source loop
         declare Next : Natural := Position; begin
            while Next /= 0 and then not Parts (Next).Done loop
               Clock;
               if Parts (Next).Visiting then Status := Corrupt; Check; end if;
               Parts (Next).Visiting := True; Stack.Append (Next); Next := Parts (Next).Dependency;
            end loop;
            for Index in reverse Stack.First_Index .. Stack.Last_Index loop
               Next := Stack.Element (Index); Order.Append (Next); Parts (Next).Done := True; Parts (Next).Visiting := False;
            end loop;
            Stack.Clear;
         end;
      end loop;
      if Natural (Order.Length) /= Chosen'Length then Status := Corrupt; Check; end if;
      for Position of Order loop Emit (Position); end loop;
      Close_Source;
      MC_SHA256.Update (Hash, Bytes'(1 .. 1_024 => 0)); Expected := MC_SHA256.Finish (Hash); Clock;
      MC_Store.Begin_Write (Store, Expected, Total, Writer, Status); Check;
      for Position of Order loop Emit (Position); end loop;
      Close_Source; Clock;
      MC_Store.Write_Chunk (Writer, Bytes'(1 .. 1_024 => 0), Status); Check;
      MC_Store.Finish_Write (Store, Writer, Status); Check; Clock; Root_Hash := Expected;
      Wire := new Bytes (1 .. Header_Size + 8 * Chosen'Length);
      Wire (1 .. 8) := Magic; Wire (9 .. 40) := Catalog; Wire (41 .. 72) := Closure;
      Wire (73 .. 104) := X.Fingerprint (Payload); Wire (105 .. 136) := Root_Hash;
      MC_Codec.Put64 (Wire.all, 137, Wide (Total)); MC_Codec.Put64 (Wire.all, 145, Wide (Chosen'Length));
      for I in Parts'Range loop MC_Codec.Put64 (Wire.all, Header_Size + 8 * (I - 1) + 1, Wide (Parts (I).Claim)); end loop;
      Clock; MC_Store.Put (Store, Wire.all, Saved, Status); Check; Clock;
      Manifest := Saved; Archive := Root_Hash; Status := OK; Cleanup;
   exception
      when Interrupted => Cleanup; Manifest := Zero_Digest; Archive := Zero_Digest;
      when Storage_Error => Cleanup; Manifest := Zero_Digest; Archive := Zero_Digest; Status := Exhausted;
      when others => Cleanup; Manifest := Zero_Digest; Archive := Zero_Digest; Status := Indeterminate;
   end Build;
   procedure Verify_Bound (Store : in out MC_Store.Store; Manifest, Catalog, Closure : Digest;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome) is
      Wire : Buffer_Access := null; File : MC_FS.File; Info : MC_FS.Entry_Info;
      Used, Count : Natural; Expected, Actual : Digest;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Cleanup is
      begin Free (Wire); MC_FS.Close (File); end Cleanup;
   begin
      Archive := Zero_Digest; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Manifest = Zero_Digest or else Limit not in 1_024 .. MC_Store.Max_Object_Size then return; end if;
      Tick (Deadline, Status); Check;
      Wire := new Bytes (1 .. Max_Manifest_Bytes);
      MC_Store.Read_Object (Store, Manifest, Wire.all, Used, Status); Check; Status := Corrupt;
      if Used < Header_Size then raise Interrupted; end if;
      if Wire (1 .. 8) /= Magic then Status := Unsupported; Check; end if;
      if MC_Codec.U64 (Wire.all, 145) not in 1 .. Wide (Max_Entries) then raise Interrupted; end if;
      Count := Natural (MC_Codec.U64 (Wire.all, 145));
      if Used /= Header_Size + 8 * Count or else MC_Codec.U64 (Wire.all, 137) not in 1_024 .. Wide (Limit)
        or else MC_Codec.U64 (Wire.all, 137) mod 512 /= 0 then raise Interrupted; end if;
      for I in 0 .. 3 loop
         if Wire (9 + 32 * I .. 40 + 32 * I) = Zero_Digest then raise Interrupted; end if;
      end loop;
      if (Catalog /= Zero_Digest and then Wire (9 .. 40) /= Catalog)
        or else (Closure /= Zero_Digest and then Wire (41 .. 72) /= Closure) then
         Status := Conflict; Check;
      end if;
      Tick (Deadline, Status); Check;
      MC_Store.Open_Object (Store, Wire (105 .. 136), File, Status); Check;
      MC_FS.Info (File, Info, Status); Check;
      if Info.Size /= Counter (MC_Codec.U64 (Wire.all, 137)) then Status := Corrupt; Check; end if;
      MC_FS.Close (File);
      declare Chosen : Selection (1 .. Count); begin
         for I in Chosen'Range loop
            if MC_Codec.U64 (Wire.all, Header_Size + 8 * (I - 1) + 1) not in 1 .. Wide (Max_Entries) then
               Status := Corrupt; Check;
            end if;
            Chosen (I) := Positive (MC_Codec.U64 (Wire.all, Header_Size + 8 * (I - 1) + 1));
         end loop;
         Build (Store, Wire (9 .. 40), Wire (41 .. 72), Chosen, Limit, Deadline, Expected, Actual, Status); Check;
      end;
      if Expected /= Manifest or else Actual /= Wire (105 .. 136) then Status := Corrupt; Check; end if;
      Tick (Deadline, Status); Check; Archive := Actual; Cleanup;
   exception
      when Interrupted => Cleanup; Archive := Zero_Digest;
      when Storage_Error => Cleanup; Archive := Zero_Digest; Status := Exhausted;
      when others => Cleanup; Archive := Zero_Digest; Status := Indeterminate;
   end Verify_Bound;
   procedure Verify (Store : in out MC_Store.Store; Manifest : Digest;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome) is
   begin Verify_Bound (Store, Manifest, Zero_Digest, Zero_Digest, Limit, Deadline, Archive, Status); end Verify;
   procedure Verify_Target (Store : in out MC_Store.Store; Manifest, Catalog, Closure : Digest;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome) is
   begin
      Archive := Zero_Digest; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input; if Catalog = Zero_Digest or else Closure = Zero_Digest then return; end if;
      Verify_Bound (Store, Manifest, Catalog, Closure, Limit, Deadline, Archive, Status);
   end Verify_Target;
end Pkg_Root_Archive;
