-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Vectors; with Ada.Containers.Ordered_Sets; with Ada.Unchecked_Deallocation;
with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix; with MC_SHA256;
with Pkg_Root_Archive; with Pkg_Deb_Payload; with Pkg_Conffile_Transition;
package body Pkg_Configured_Root_Record with SPARK_Mode => Off is
   use type Interfaces.C.unsigned; use type MC_FS.Entry_Info; use type Wide; use type Word; use type Byte;
   package Choices is new Ada.Containers.Vectors (Positive, Saved_Choice);
   package Configurations is new Ada.Containers.Vectors (Positive, Saved_Configuration);
   package Addresses is new Ada.Containers.Vectors (Positive, Digest);
   package Objects is new Ada.Containers.Ordered_Sets (Digest);
   type Data is record
      Bound : Root_Binding;
      Selected : Choices.Vector;
      Configured : Configurations.Vector;
      Members : Addresses.Vector;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out View) is begin Free (Value.State); end Clear;
   overriding procedure Finalize (Value : in out View) is begin Clear (Value); end Finalize;
   function Binding (Value : View) return Root_Binding is
     (if Value.State = null then (others => <>) else Value.State.Bound);
   function Choice_Count (Value : View) return Natural is
     (if Value.State = null then 0 else Natural (Value.State.Selected.Length));
   function Configuration_Count (Value : View) return Natural is
     (if Value.State = null then 0 else Natural (Value.State.Configured.Length));
   function Object_Count (Value : View) return Natural is
     (if Value.State = null then 0 else Natural (Value.State.Members.Length));
   procedure Read_Choice (Value : View; Position : Positive;
      Item : out Saved_Choice; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position <= Choice_Count (Value) then Item := Value.State.Selected (Position); Status := OK; end if;
   end Read_Choice;
   procedure Read_Configuration (Value : View; Position : Positive;
      Item : out Saved_Configuration; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position <= Configuration_Count (Value) then Item := Value.State.Configured (Position); Status := OK; end if;
   end Read_Configuration;
   procedure Read_Object (Value : View; Position : Positive; Item : out Digest; Status : out Outcome) is
   begin
      Item := Zero_Digest; Status := Invalid_Input;
      if Position <= Object_Count (Value) then Item := Value.State.Members (Position); Status := OK; end if;
   end Read_Object;
   procedure Load (Store : MC_Store.Store; Manifest, Retained : Digest;
      Limit, Deadline : Counter; Value : in out View; Status : out Outcome) is
      type Reader is limited record
         File : MC_FS.File;
         Before : MC_FS.Entry_Info;
         Address : Digest;
         Offset : Counter := 0;
         Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      end record;
      Input : Reader; Object_File : MC_FS.File;
      Candidate : Data_Access := null;
      Expected, Actual, Seen_Proposals : Objects.Set;
      Header : Bytes (1 .. Header_Size); Row : Bytes (1 .. 96);
      Count, Choice_Total, Configured_Total, Previous_Position : Natural := 0;
      Previous, Member, Payload : Digest := Zero_Digest;
      Interrupted : exception;
      procedure Need is begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Refuse (Reason : Outcome := Corrupt) is begin Status := Reason; raise Interrupted; end Refuse;
      procedure Tick is
         Now : Counter;
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status); Need;
         if Deadline = Counter'Last or else Now >= Deadline then Refuse (Stale); end if;
      end Tick;
      procedure Cleanup is begin MC_FS.Close (Input.File); MC_FS.Close (Object_File); Free (Candidate); end Cleanup;
      procedure Open (Address : Digest; Maximum : Counter) is
      begin
         Tick; MC_Store.Open_Object (Store, Address, Input.File, Status); Need;
         MC_FS.Info (Input.File, Input.Before, Status); Need;
         if Input.Before.Size > Maximum then Refuse (Exhausted); end if;
         Input.Address := Address; Input.Offset := 0; Input.Hash := MC_SHA256.Initialize;
      end Open;
      procedure Read (Buffer : out Bytes) is
         Used : Natural;
      begin
         Tick; MC_FS.Read_At (Input.File, Input.Offset, Buffer, Used, Status); Need;
         if Used /= Buffer'Length then Refuse; end if;
         MC_SHA256.Update (Input.Hash, Buffer); Input.Offset := Input.Offset + Counter (Used);
      end Read;
      procedure Finish is
         After : MC_FS.Entry_Info;
      begin
         MC_FS.Info (Input.File, After, Status); Need;
         if After /= Input.Before or else MC_SHA256.Finish (Input.Hash) /= Input.Address then Refuse (Stale); end if;
         if Input.Offset /= Input.Before.Size then Refuse; end if;
         MC_FS.Close (Input.File); Tick;
      end Finish;
      procedure Include (Address : Digest) is
      begin
         if Address = Zero_Digest then Refuse; end if;
         Expected.Include (Address);
         if Natural (Expected.Length) > Max_Objects then Refuse (Exhausted); end if;
      end Include;
      procedure Size_Is (Address : Digest; Size : Counter) is
         Info : MC_FS.Entry_Info;
      begin
         Tick; MC_Store.Open_Object (Store, Address, Object_File, Status); Need;
         MC_FS.Info (Object_File, Info, Status); Need; MC_FS.Close (Object_File);
         if Info.Size /= Size then Refuse; end if;
      end Size_Is;
      procedure Collect (Address : Digest; Choice : Boolean; Reference : Saved_Choice := (others => <>)) is
         Wire : Bytes (1 .. 80); Length, Members : Natural; Last, Item : Digest := Zero_Digest;
      begin
         Include (Address); Length := (if Choice then 76 else 80);
         Open (Address, Counter (Length + 32 * (if Choice then 32 else Pkg_Catalog_Retention.Max_Objects)));
         Read (Wire (1 .. Length));
         if Choice then
            if Wire (1 .. 8) /= Bytes'(78, 73, 65, 67, 67, 70, 48, 49)
               or else Wire (9 .. 40) /= Reference.Proposal or else Wire (41 .. 72) /= Reference.Decision
               or else MC_Codec.U32 (Wire, 73) not in 1 .. 32 then Refuse; end if;
            Members := Natural (MC_Codec.U32 (Wire, 73));
         else
            if Wire (1 .. 8) /= Bytes'(78, 73, 65, 67, 76, 79, 83, 49)
               or else Wire (9 .. 40) /= Candidate.Bound.Base.Catalog or else Wire (41 .. 72) /= Payload
               or else MC_Codec.U64 (Wire, 73) not in 1 .. Wide (Pkg_Catalog_Retention.Max_Objects) then Refuse; end if;
            Members := Natural (MC_Codec.U64 (Wire, 73));
         end if;
         if Input.Before.Size /= Counter (Length + 32 * Members) then Refuse; end if;
         for I in 1 .. Members loop
            Read (Item); if Item <= Last then Refuse; end if; Last := Item; Include (Item);
         end loop;
         Finish;
      end Collect;
      procedure Check_Choice (Reference : Saved_Choice) is
         type Positive_Array is array (Positive range <>) of Positive;
         Proposal : Bytes (1 .. 344); Decision : Bytes (1 .. 368);
         Path : Bytes (1 .. Pkg_Deb_Payload.Max_Name); Length : Natural;
         procedure Required (Address : Digest) is
         begin if Address /= Zero_Digest and then not Actual.Contains (Address) then Refuse; end if; end Required;
         procedure Tail (Base : Natural; At_Byte : Positive; Wire : Bytes; Empty : Boolean) is
         begin
            if MC_Codec.U32 (Wire, At_Byte) > Word (Path'Length) then Refuse (Exhausted); end if;
            Length := Natural (MC_Codec.U32 (Wire, At_Byte));
            if Input.Before.Size /= Counter (Base + Length) or else (not Empty and then Length = 0) then Refuse; end if;
            Read (Path (1 .. Length));
            if Length > 0 and then (Path (1) /= 47 or else (for some B of Path (1 .. Length) => B = 0)) then Refuse; end if;
            Finish;
         end Tail;
      begin
         Open (Reference.Proposal, 344 + Pkg_Deb_Payload.Max_Name); Read (Proposal);
         if Proposal (1 .. 8) /= Bytes'(78, 73, 65, 67, 80, 82, 48, 49)
            or else Proposal (9 .. 24) /= Candidate.Bound.Base.Root_ID
            or else Proposal (25 .. 40) /= Candidate.Bound.Base.Transaction
            or else Proposal (41 .. 72) /= Candidate.Bound.Base.Context
            or else Proposal (329) > Pkg_Conffile_Transition.Operation'Pos (Pkg_Conffile_Transition.Operation'Last)
            or else Proposal (330) > 1 or else Proposal (331) > 1 or else Proposal (332) > 1
            or else MC_Codec.U64 (Proposal, 333) not in 1 .. Wide (Counter'Last - 1) then Refuse; end if;
         for I in 0 .. 7 loop Required (Proposal (73 + 32 * I .. 104 + 32 * I)); end loop;
         Tail (344, 341, Proposal, False);
         Open (Reference.Decision, 368 + Pkg_Deb_Payload.Max_Name); Read (Decision);
         if Decision (1 .. 8) /= Bytes'(78, 73, 65, 67, 67, 72, 48, 50)
            or else Decision (9 .. 40) /= Reference.Proposal or else Decision (41) > 2
            or else Decision (42) > 4 or else Decision (42) = 2 or else Decision (43) > 2 or else Decision (44) > 1 then Refuse; end if;
         for I in 0 .. 4 loop Required (Decision (45 + 32 * I .. 76 + 32 * I)); end loop;
         for Start of Positive_Array'(209, 289) loop
            if Decision (Start) > 2 or else Decision (Start + 1 .. Start + 3) /= Bytes'(0, 0, 0)
               or else MC_Codec.U32 (Decision, Start + 4) > 8#7777# then Refuse; end if;
            Required (Decision (Start + 16 .. Start + 47)); Required (Decision (Start + 48 .. Start + 79));
         end loop;
         Tail (368, 205, Decision, True);
      end Check_Choice;
   begin
      Clear (Value); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Manifest = Zero_Digest or else Retained = Zero_Digest or else Limit not in 1_024 .. MC_Store.Max_Object_Size
         or else MC_Store.Native_Reservation (Store) < 0 then return; end if;
      Tick; Candidate := new Data;
      Open (Retained, Retention_Header_Size + 32 * Max_Objects); Read (Header (1 .. Retention_Header_Size));
      if Header (1 .. 8) /= Bytes'(78, 73, 65, 67, 82, 67, 48, 49) or else Header (9 .. 40) /= Manifest
         or else MC_Codec.U64 (Header, 41) not in 1 .. Wide (Max_Objects) then Refuse; end if;
      Count := Natural (MC_Codec.U64 (Header, 41));
      if Input.Before.Size /= Counter (Retention_Header_Size + 32 * Count) then Refuse; end if;
      for I in 1 .. Count loop
         Read (Member); if Member <= Previous then Refuse; end if;
         Previous := Member; Actual.Insert (Member); Candidate.Members.Append (Member);
         MC_Store.Open_Object (Store, Member, Object_File, Status); Need; MC_FS.Close (Object_File);
      end loop;
      Finish;
      Open (Manifest, Max_Manifest_Bytes); Read (Header);
      if Header (1 .. 8) /= Bytes'(78, 73, 65, 67, 82, 84, 48, 49) then Refuse (Unsupported); end if;
      Candidate.Bound.Base := (Manifest => Header (9 .. 40), Catalog => Header (41 .. 72),
         Closure => Header (73 .. 104), Archive => Header (105 .. 136), Ownership => Header (137 .. 168),
         Root_ID => Header (169 .. 184), Transaction => Header (185 .. 200), Context => Header (201 .. 232));
      Candidate.Bound.Architecture := Header (233 .. 264); Candidate.Bound.Archive := Header (265 .. 296);
      if Candidate.Bound.Base.Ownership = Zero_Digest or else Candidate.Bound.Base.Root_ID = Zero_Identity
         or else Candidate.Bound.Base.Transaction = Zero_Identity or else Candidate.Bound.Base.Context = Zero_Digest
         or else Candidate.Bound.Architecture = Zero_Digest then Refuse; end if;
      if MC_Codec.U64 (Header, 297) not in 1_024 .. Wide (Limit) then Refuse (Exhausted); end if;
      if MC_Codec.U64 (Header, 305) not in 1 .. Wide (Pkg_Root_Archive.Max_Entries)
         or else MC_Codec.U32 (Header, 313) > Word (Pkg_Root_Configuration.Max_Choices)
         or else MC_Codec.U32 (Header, 317) > Word (Max_Configurations) then Refuse (Exhausted); end if;
      Candidate.Bound.Size := Counter (MC_Codec.U64 (Header, 297)); Candidate.Bound.Entries := Counter (MC_Codec.U64 (Header, 305));
      Choice_Total := Natural (MC_Codec.U32 (Header, 313)); Configured_Total := Natural (MC_Codec.U32 (Header, 317));
      if Candidate.Bound.Size mod 512 /= 0 or else Configured_Total > 2 * Choice_Total
         or else Counter (Configured_Total) >= Candidate.Bound.Entries
         or else Input.Before.Size /= Counter (Header_Size + 96 * Choice_Total + 80 * Configured_Total) then Refuse; end if;
      Include (Manifest); Include (Candidate.Bound.Base.Manifest); Include (Candidate.Bound.Base.Archive);
      Include (Candidate.Bound.Base.Catalog); Include (Candidate.Bound.Archive);
      for I in 1 .. Choice_Total loop
         Read (Row);
         declare Item : constant Saved_Choice := (Row (1 .. 32), Row (33 .. 64), Row (65 .. 96)); begin
            if Seen_Proposals.Contains (Item.Proposal) then Refuse; end if; Seen_Proposals.Insert (Item.Proposal);
            Include (Item.Proposal); Include (Item.Decision); Include (Item.Closure); Candidate.Selected.Append (Item);
         end;
      end loop;
      for I in 1 .. Configured_Total loop
         Read (Row (1 .. 80));
         if MC_Codec.U64 (Row, 1) not in 2 .. Wide (Candidate.Bound.Entries)
            or else MC_Codec.U64 (Row, 73) > Wide (Limit) then Refuse; end if;
         declare Item : constant Saved_Configuration :=
            (Natural (MC_Codec.U64 (Row, 1)), Row (9 .. 40), Row (41 .. 72), Counter (MC_Codec.U64 (Row, 73))); begin
            if Item.Position <= Previous_Position then Refuse; end if; Previous_Position := Item.Position;
            Include (Item.Prefix); Include (Item.Content); Candidate.Configured.Append (Item);
         end;
      end loop;
      Finish;
      Size_Is (Candidate.Bound.Archive, Candidate.Bound.Size);
      Open (Candidate.Bound.Base.Manifest, Pkg_Root_Archive.Max_Manifest_Bytes); Read (Header (1 .. Pkg_Root_Archive.Header_Size));
      if Header (1 .. 7) /= Bytes'(78, 73, 65, 82, 79, 79, 84) or else Header (8) not in 49 .. 50
         or else Header (9 .. 40) /= Candidate.Bound.Base.Catalog or else Header (41 .. 72) /= Candidate.Bound.Base.Closure
         or else Header (73 .. 104) = Zero_Digest or else Header (105 .. 136) /= Candidate.Bound.Base.Archive
         or else MC_Codec.U64 (Header, 137) not in 1_024 .. Wide (Limit)
         or else MC_Codec.U64 (Header, 145) not in 1 .. Wide (Pkg_Root_Archive.Max_Entries) then Refuse; end if;
      Payload := Header (73 .. 104); Size_Is (Candidate.Bound.Base.Archive, Counter (MC_Codec.U64 (Header, 137)));
      Count := Natural (MC_Codec.U64 (Header, 145));
      if Input.Before.Size /= Counter (Pkg_Root_Archive.Header_Size + 8 * Count) then Refuse; end if;
      for I in 1 .. Count loop
         Read (Row (1 .. 8)); if MC_Codec.U64 (Row, 1) not in 1 .. Wide (Pkg_Root_Archive.Max_Entries) then Refuse; end if;
      end loop;
      Finish;
      Collect (Candidate.Bound.Base.Closure, False);
      for Item of Candidate.Selected loop Collect (Item.Closure, True, Item); Check_Choice (Item); end loop;
      for Item of Candidate.Configured loop
         Size_Is (Item.Content, Item.Size);
         declare Info : MC_FS.Entry_Info; begin
            Tick; MC_Store.Open_Object (Store, Item.Prefix, Object_File, Status); Need;
            MC_FS.Info (Object_File, Info, Status); Need; MC_FS.Close (Object_File);
            if Info.Size < 512 or else Info.Size mod 512 /= 0 or else Info.Size > Candidate.Bound.Size - 1_024
               or else Item.Size > Candidate.Bound.Size - 1_024 - Info.Size then Refuse; end if;
         end;
      end loop;
      if not Objects."=" (Expected, Actual) then Refuse; end if;
      Tick; Value.State := Candidate; Candidate := null; Status := OK;
   exception
      when Interrupted => Cleanup; Clear (Value);
      when Storage_Error => Cleanup; Clear (Value); Status := Exhausted;
      when others => Cleanup; Clear (Value); Status := Indeterminate;
   end Load;
end Pkg_Configured_Root_Record;
