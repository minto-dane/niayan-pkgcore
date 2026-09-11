-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Vectors; with Ada.Containers.Ordered_Sets; with Ada.Unchecked_Deallocation;
with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix; with MC_SHA256;
with Pkg_Configuration_Entry; with Pkg_Conffile_Choice; with Pkg_Deb_Payload;
with Pkg_Payload_Index; with Pkg_Catalog_Store; with Pkg_Selected_Catalog; with Pkg_Tar_Framing;
with Pkg_Catalog_Retention;
package body Pkg_Configured_Root with SPARK_Mode => Off is
   package R renames Pkg_Root_Configuration; package C renames Pkg_Conffile_Choice;
   package P renames Pkg_Deb_Payload; package X renames Pkg_Payload_Index; package T renames Pkg_Tar_Framing;
   use type Interfaces.C.unsigned; use type MC_FS.Entry_Info; use type P.Entry_Kind; use type Wide; use type Word;
   Magic : constant Bytes := (78, 73, 65, 67, 82, 84, 48, 49);
   Retention_Magic : constant Bytes := (78, 73, 65, 67, 82, 67, 48, 49);
   package Objects is new Ada.Containers.Ordered_Sets (Digest);
   function Padded (Size : Counter) return Counter is
     (Size + (if Size mod 512 = 0 then 0 else 512 - Size mod 512));
   procedure Tick (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then (Deadline = Counter'Last or else Now >= Deadline) then Status := Stale; end if;
   end Tick;
   procedure Build (Store : in out MC_Store.Store; Base_Manifest, Catalog, Catalog_Closure : Digest;
      Root_ID, Transaction : Identity; Context : Digest; Native_Architecture : String;
      Selected : R.Choices; Limit, Deadline : Counter;
      Manifest, Archive, Retained : out Digest; Status : out Outcome) is
      type Part is record
         Source, Ordinal, Dependency : Natural := 0;
         First, Length, Size : Counter := 0;
         Prefix, Content : Digest := Zero_Digest;
         Directory, Done, Visiting : Boolean := False;
      end record;
      type Part_Array is array (Positive range <>) of Part;
      type Part_Access is access Part_Array;
      procedure Free is new Ada.Unchecked_Deallocation (Part_Array, Part_Access);
      type Source_Info is record Source : X.Package_Source; Stat : MC_FS.Entry_Info; end record;
      type Source_Array is array (Positive range <>) of Source_Info;
      type Source_Access is access Source_Array;
      procedure Free is new Ada.Unchecked_Deallocation (Source_Array, Source_Access);
      package Positions is new Ada.Containers.Vectors (Positive, Positive);
      Layout : R.Layout; Binding : R.Input_Binding; Base : Pkg_Selected_Catalog.Catalog; Payload : X.Index;
      Parts : Part_Access := null; Sources : Source_Access := null;
      By_Source, Order, Stack : Positions.Vector; Members : Objects.Set;
      File, Object_File : MC_FS.File; Writer : MC_Store.Writer; Frames : T.Index;
      Current_Source, Configured, Comparisons : Natural := 0;
      Total : Counter := 1_024; Saved_Manifest, Saved_Root, Expected : Digest := Zero_Digest;
      Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Buffer : Bytes (1 .. 65_536); Writing : Boolean := False;
      Interrupted : exception;
      procedure Need is begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Clock is begin Tick (Deadline, Status); Need; end Clock;
      procedure Refuse (Reason : Outcome := Corrupt) is begin Status := Reason; raise Interrupted; end Refuse;
      procedure Cleanup is
      begin
         MC_FS.Close (File); MC_FS.Close (Object_File); MC_Store.Abort_Write (Writer);
         Free (Parts); Free (Sources); R.Clear (Layout);
      end Cleanup;
      procedure Include (Address : Digest) is
      begin
         if Address = Zero_Digest then Refuse; end if;
         Members.Include (Address); if Natural (Members.Length) > Max_Objects then Refuse (Exhausted); end if;
      end Include;
      procedure Recheck is
      begin
         for Ref of Selected loop
            Clock; C.Recheck (Store, Ref.Value.all, Ref.Decision, Ref.Closure, Deadline, Status); Need;
         end loop;
      end Recheck;
      function Path_At (Position : Positive) return String is
         Layout_Entry : R.Entry_Reference;
      begin
         R.Read_Entry (Layout, Position, Layout_Entry, Status); Need; return P.Byte_Strings.To_String (Layout_Entry.Path);
      end Path_At;
      function Find (Name : String) return Natural is
         First : Positive := 1; Last : Positive := R.Count (Layout) + 1; Middle : Positive;
      begin
         while First < Last loop
            Clock; Middle := First + (Last - First) / 2;
            if Path_At (Middle) < Name then First := Middle + 1; else Last := Middle; end if;
         end loop;
         return (if First <= R.Count (Layout) and then Path_At (First) = Name then First else 0);
      end Find;
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
         Comparisons := Comparisons + 1;
         if Comparisons = 1_024 then Clock; Comparisons := 0; end if;
         return Parts (Left).Source < Parts (Right).Source or else
           (Parts (Left).Source = Parts (Right).Source and then Parts (Left).Ordinal < Parts (Right).Ordinal);
      end Less;
      package Sorting is new Positions.Generic_Sorting (Less);
      procedure Close_Source is
         After : MC_FS.Entry_Info;
      begin
         if Current_Source = 0 then return; end if;
         MC_FS.Info (File, After, Status); Need;
         if After /= Sources (Current_Source).Stat then Refuse (Stale); end if;
         MC_FS.Close (File); Current_Source := 0; Clock;
      end Close_Source;
      procedure Open_Source (Number : Positive; Remember : Boolean := False) is
         Info : MC_FS.Entry_Info;
      begin
         if Current_Source = Number then return; end if;
         Close_Source; Clock; MC_Store.Open_Object (Store, Sources (Number).Source.Tar, File, Status); Need;
         MC_FS.Info (File, Info, Status); Need;
         if Remember then Sources (Number).Stat := Info;
         elsif Info /= Sources (Number).Stat then Refuse (Stale); end if;
         Current_Source := Number; Clock;
      end Open_Source;
      procedure Feed (Data : Bytes) is
      begin
         Clock;
         if Writing then MC_Store.Write_Chunk (Writer, Data, Status); Need;
         else MC_SHA256.Update (Hash, Data); end if;
      end Feed;
      procedure Copy_Range (Input : MC_FS.File; First, Length : Counter) is
         Offset : Counter := 0; Take, Used : Natural;
      begin
         while Offset < Length loop
            Clock; Take := Natural (Counter'Min (Buffer'Length, Length - Offset));
            MC_FS.Read_At (Input, First + Offset, Buffer (1 .. Take), Used, Status); Need;
            if Used /= Take then Refuse; end if;
            Feed (Buffer (1 .. Used)); Offset := Offset + Counter (Used);
         end loop;
      end Copy_Range;
      procedure Copy_Object (Address : Digest; Length : Counter) is
         Before, After : MC_FS.Entry_Info;
      begin
         MC_Store.Open_Object (Store, Address, Object_File, Status); Need;
         MC_FS.Info (Object_File, Before, Status); Need; if Before.Size /= Length then Refuse; end if;
         Copy_Range (Object_File, 0, Length);
         MC_FS.Info (Object_File, After, Status); Need; if Before /= After then Refuse (Stale); end if;
         MC_FS.Close (Object_File);
      end Copy_Object;
      procedure Emit_Root is
      begin
         for Position of Order loop
            if Parts (Position).Source /= 0 then
               Open_Source (Parts (Position).Source); Copy_Range (File, Parts (Position).First, Parts (Position).Length);
            else
               Close_Source; Copy_Object (Parts (Position).Prefix, Parts (Position).Length);
               Copy_Object (Parts (Position).Content, Parts (Position).Size);
               Feed (Bytes'(1 .. Natural (Padded (Parts (Position).Size) - Parts (Position).Size) => 0));
            end if;
         end loop;
         Close_Source; Feed (Bytes'(1 .. 1_024 => 0));
      end Emit_Root;
      procedure Collect (Address : Digest; Choice : Boolean; Proposal, Decision : Digest := Zero_Digest) is
         Header : Bytes (1 .. 80); Info, After : MC_FS.Entry_Info; Used, Count, Length : Natural;
         Check_Hash : MC_SHA256.Context := MC_SHA256.Initialize;
         Previous, Member : Digest := Zero_Digest;
      begin
         Include (Address); MC_Store.Open_Object (Store, Address, Object_File, Status); Need;
         MC_FS.Info (Object_File, Info, Status); Need; Length := (if Choice then 76 else 80);
         MC_FS.Read_At (Object_File, 0, Header (1 .. Length), Used, Status); Need; if Used /= Length then Refuse; end if;
         if Choice then
            if Header (1 .. 8) /= Bytes'(78, 73, 65, 67, 67, 70, 48, 49) or else Header (9 .. 40) /= Proposal
               or else Header (41 .. 72) /= Decision or else MC_Codec.U32 (Header, 73) not in 1 .. 32 then Refuse; end if;
            Count := Natural (MC_Codec.U32 (Header, 73));
         else
            if Header (1 .. 8) /= Bytes'(78, 73, 65, 67, 76, 79, 83, 49) or else Header (9 .. 40) /= Catalog
               or else Header (41 .. 72) /= X.Fingerprint (Payload)
               or else MC_Codec.U64 (Header, 73) not in 1 .. Wide (Pkg_Catalog_Retention.Max_Objects) then Refuse; end if;
            Count := Natural (MC_Codec.U64 (Header, 73));
         end if;
         if Info.Size /= Counter (Length + 32 * Count) then Refuse; end if;
         MC_SHA256.Update (Check_Hash, Header (1 .. Length));
         for I in 1 .. Count loop
            Clock; MC_FS.Read_At (Object_File, Counter (Length + 32 * (I - 1)), Member, Used, Status); Need;
            if Used /= 32 or else Member <= Previous then Refuse; end if;
            Include (Member); Previous := Member; MC_SHA256.Update (Check_Hash, Member);
         end loop;
         MC_FS.Info (Object_File, After, Status); Need;
         if Info /= After or else MC_SHA256.Finish (Check_Hash) /= Address then Refuse (Stale); end if;
         MC_FS.Close (Object_File);
      end Collect;
      procedure Emit_Manifest is
         Header : Bytes (1 .. Header_Size) := (others => 0); Row : Bytes (1 .. 96); Choice : R.Choice_Binding;
      begin
         Header (1 .. 8) := Magic; Header (9 .. 40) := Base_Manifest; Header (41 .. 72) := Catalog;
         Header (73 .. 104) := Catalog_Closure; Header (105 .. 136) := Binding.Archive; Header (137 .. 168) := Binding.Ownership;
         Header (169 .. 184) := Root_ID; Header (185 .. 200) := Transaction; Header (201 .. 232) := Context;
         declare Text : Bytes (1 .. Native_Architecture'Length); begin
            for I in Text'Range loop Text (I) := Character'Pos (Native_Architecture (Native_Architecture'First + I - 1)); end loop;
            Header (233 .. 264) := MC_SHA256.Hash (Text);
         end;
         Header (265 .. 296) := Saved_Root; MC_Codec.Put64 (Header, 297, Wide (Total));
         MC_Codec.Put64 (Header, 305, Wide (R.Count (Layout))); MC_Codec.Put32 (Header, 313, Word (R.Choice_Count (Layout)));
         MC_Codec.Put32 (Header, 317, Word (Configured)); Feed (Header);
         for I in 1 .. R.Choice_Count (Layout) loop
            R.Read_Choice (Layout, I, Choice, Status); Need;
            Row (1 .. 32) := Choice.Proposal; Row (33 .. 64) := Choice.Decision; Row (65 .. 96) := Choice.Closure; Feed (Row);
         end loop;
         for I in Parts'Range loop
            if Parts (I).Source = 0 then
               MC_Codec.Put64 (Row, 1, Wide (I)); Row (9 .. 40) := Parts (I).Prefix; Row (41 .. 72) := Parts (I).Content;
               MC_Codec.Put64 (Row, 73, Wide (Parts (I).Size)); Feed (Row (1 .. 80));
            end if;
         end loop;
      end Emit_Manifest;
      procedure Emit_Retention is
         Header : Bytes (1 .. Retention_Header_Size);
      begin
         Header (1 .. 8) := Retention_Magic; Header (9 .. 40) := Saved_Manifest;
         MC_Codec.Put64 (Header, 41, Wide (Members.Length)); Feed (Header);
         for Member of Members loop Feed (Member); end loop;
      end Emit_Retention;
   begin
      Manifest := Zero_Digest; Archive := Zero_Digest; Retained := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Limit not in 1_024 .. MC_Store.Max_Object_Size or else MC_Store.Native_Reservation (Store) < 0 then return; end if;
      Clock; R.Prepare (Store, Base_Manifest, Catalog, Catalog_Closure, Root_ID, Transaction, Context,
         Native_Architecture, Selected, Limit, Deadline, Layout, Status); Need; Binding := R.Binding (Layout);
      if R.Count (Layout) not in 1 .. Pkg_Root_Archive.Max_Entries then Refuse (Exhausted); end if;
      Pkg_Catalog_Store.Load (Store, Catalog, Deadline, Base, Payload, Status); Need;
      Parts := new Part_Array (1 .. R.Count (Layout)); Sources := new Source_Array (1 .. X.Package_Count (Payload));
      for I in Sources'Range loop Clock; X.Read_Package (Payload, I, Sources (I).Source, Status); Need; end loop;
      for I in Parts'Range loop
         Clock;
         declare Layout_Entry : R.Entry_Reference; Claim : X.Claim; Info : MC_FS.Entry_Info; begin
            R.Read_Entry (Layout, I, Layout_Entry, Status); Need;
            if Layout_Entry.Base_Claim /= 0 then
               X.Read_Claim (Payload, Layout_Entry.Base_Claim, Claim, Status); Need;
               Parts (I).Source := Source_Number (Claim.Source.Original); Parts (I).Ordinal := Claim.Source_Position;
               if Parts (I).Source = 0 or else Claim.Source.Tar /= Sources (Parts (I).Source).Source.Tar then Refuse; end if;
               Parts (I).Directory := Claim.Item.Values.Kind = P.Directory;
               if Claim.Item.Values.Kind = P.Hard_Link then
                  Parts (I).Dependency := Find (P.Byte_Strings.To_String (Claim.Item.Link_Target));
                  if Parts (I).Dependency = 0 then Refuse (Conflict); end if;
               end if;
               By_Source.Append (I);
            else
               Pkg_Configuration_Entry.Prepare (Store, Layout_Entry.Configuration, Deadline, Parts (I).Prefix, Parts (I).Size, Status); Need;
               Parts (I).Content := Layout_Entry.Configuration.Content;
               MC_Store.Open_Object (Store, Parts (I).Prefix, Object_File, Status); Need;
               MC_FS.Info (Object_File, Info, Status); Need; MC_FS.Close (Object_File); Parts (I).Length := Info.Size;
               Include (Parts (I).Prefix); Include (Parts (I).Content); Configured := Configured + 1;
               if Info.Size > Limit - Total then Refuse (Exhausted); end if; Total := Total + Info.Size;
               if Padded (Parts (I).Size) > Limit - Total then Refuse (Exhausted); end if; Total := Total + Padded (Parts (I).Size);
            end if;
         end;
      end loop;
      Sorting.Sort (By_Source);
      for Position of By_Source loop
         Clock;
         if Current_Source /= Parts (Position).Source then
            Open_Source (Parts (Position).Source, True); T.Scan (File, Sources (Current_Source).Stat.Size, Deadline, Frames, Status); Need;
            if T.Count (Frames) /= Sources (Current_Source).Source.Entries then Refuse; end if;
         end if;
         declare F : constant T.Frame := T.At_Index (Frames, Parts (Position).Ordinal); begin
            if Parts (Position).Ordinal > 1 then
               declare Previous : constant T.Frame := T.At_Index (Frames, Parts (Position).Ordinal - 1); begin
                  Parts (Position).First := Previous.Body_Start + Padded (Previous.Size);
               end;
            end if;
            if F.Body_Start + Padded (F.Size) <= Parts (Position).First then Refuse; end if;
            Parts (Position).Length := F.Body_Start + Padded (F.Size) - Parts (Position).First;
            if Parts (Position).Length > Limit - Total then Refuse (Exhausted); end if; Total := Total + Parts (Position).Length;
            if Parts (Position).Dependency /= 0 and then Parts (Parts (Position).Dependency).Source /= Parts (Position).Source then Refuse (Conflict); end if;
         end;
      end loop;
      Close_Source;
      if Path_At (1) /= "" or else not Parts (1).Directory then Refuse; end if;
      for I in Parts'Range loop
         if Parts (I).Directory then Order.Append (I); Parts (I).Done := True; end if;
      end loop;
      for Position of By_Source loop
         declare Next : Natural := Position; begin
            while Next /= 0 and then not Parts (Next).Done loop
               Clock; if Parts (Next).Visiting then Refuse; end if;
               Parts (Next).Visiting := True; Stack.Append (Next); Next := Parts (Next).Dependency;
            end loop;
            for I in reverse Stack.First_Index .. Stack.Last_Index loop
               Next := Stack.Element (I); Order.Append (Next); Parts (Next).Done := True; Parts (Next).Visiting := False;
            end loop;
            Stack.Clear;
         end;
      end loop;
      for I in Parts'Range loop if Parts (I).Source = 0 then Order.Append (I); end if; end loop;
      if Natural (Order.Length) /= R.Count (Layout) then Refuse; end if;
      Emit_Root; Expected := MC_SHA256.Finish (Hash); Recheck;
      MC_Store.Begin_Write (Store, Expected, Total, Writer, Status); Need; Writing := True; Emit_Root;
      MC_Store.Finish_Write (Store, Writer, Status); Need; Saved_Root := Expected; Writing := False;
      Hash := MC_SHA256.Initialize; Emit_Manifest; Expected := MC_SHA256.Finish (Hash);
      MC_Store.Begin_Write (Store, Expected, Counter (Header_Size + 96 * R.Choice_Count (Layout) + 80 * Configured), Writer, Status); Need;
      Writing := True; Emit_Manifest; MC_Store.Finish_Write (Store, Writer, Status); Need; Saved_Manifest := Expected; Writing := False;
      Include (Saved_Manifest); Include (Saved_Root); Include (Base_Manifest); Include (Binding.Archive);
      Collect (Catalog_Closure, False);
      for I in 1 .. R.Choice_Count (Layout) loop
         declare Choice : R.Choice_Binding; begin
            R.Read_Choice (Layout, I, Choice, Status); Need;
            Include (Choice.Proposal); Include (Choice.Decision); Collect (Choice.Closure, True, Choice.Proposal, Choice.Decision);
         end;
      end loop;
      for Member of Members loop
         Clock; MC_Store.Open_Object (Store, Member, Object_File, Status); Need; MC_FS.Close (Object_File);
      end loop;
      Hash := MC_SHA256.Initialize; Emit_Retention; Expected := MC_SHA256.Finish (Hash);
      MC_Store.Begin_Write (Store, Expected, Counter (Retention_Header_Size + 32 * Natural (Members.Length)), Writer, Status); Need;
      Writing := True; Emit_Retention; MC_Store.Finish_Write (Store, Writer, Status); Need;
      Recheck; Clock; Manifest := Saved_Manifest; Archive := Saved_Root; Retained := Expected; Cleanup;
   exception
      when Interrupted => Cleanup; Manifest := Zero_Digest; Archive := Zero_Digest; Retained := Zero_Digest;
      when Storage_Error => Cleanup; Manifest := Zero_Digest; Archive := Zero_Digest; Retained := Zero_Digest; Status := Exhausted;
      when others => Cleanup; Manifest := Zero_Digest; Archive := Zero_Digest; Retained := Zero_Digest; Status := Indeterminate;
   end Build;
   procedure Verify (Store : in out MC_Store.Store; Manifest, Retained : Digest;
      Base_Manifest, Catalog, Catalog_Closure : Digest; Root_ID, Transaction : Identity;
      Context : Digest; Native_Architecture : String; Selected : R.Choices;
      Limit, Deadline : Counter; Archive : out Digest; Status : out Outcome) is
      Saved : Pkg_Configured_Root_Record.View;
      Got_Manifest, Got_Archive, Got_Retained : Digest;
      Interrupted : exception;
      procedure Need is begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Cleanup is begin Pkg_Configured_Root_Record.Clear (Saved); end Cleanup;
   begin
      Archive := Zero_Digest; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input; if Manifest = Zero_Digest or else Retained = Zero_Digest then return; end if;
      Tick (Deadline, Status); Need;
      Pkg_Configured_Root_Record.Load (Store, Manifest, Retained, Limit, Deadline, Saved, Status); Need;
      Cleanup;
      Build (Store, Base_Manifest, Catalog, Catalog_Closure, Root_ID, Transaction, Context, Native_Architecture,
         Selected, Limit, Deadline, Got_Manifest, Got_Archive, Got_Retained, Status); Need;
      if Got_Manifest /= Manifest or else Got_Retained /= Retained then Status := Conflict; raise Interrupted; end if;
      Archive := Got_Archive;
   exception
      when Interrupted => Cleanup; Archive := Zero_Digest;
      when Storage_Error => Cleanup; Archive := Zero_Digest; Status := Exhausted;
      when others => Cleanup; Archive := Zero_Digest; Status := Indeterminate;
   end Verify;
end Pkg_Configured_Root;
