-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Ordered_Sets; with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix; with MC_SHA256;
with Pkg_Conffile_Snapshot; with Pkg_Deb_Conffiles; with Pkg_Deb_Payload;
with Pkg_Conffile_Observation;
package body Pkg_Conffile_Choice with SPARK_Mode => Off is
   package T renames Pkg_Conffile_Transition; package S renames Pkg_Conffile_Snapshot;
   package D renames Pkg_Deb_Conffiles; package P renames Pkg_Deb_Payload;
   package Objects is new Ada.Containers.Ordered_Sets (Digest);
   use type Interfaces.C.int; use type Interfaces.C.unsigned;
   use type T.File_Kind; use type T.Action; use type T.Backup_Kind; use type T.Choice; use type P.Entry_Kind;
   use type Word; use type Wide; use type Byte;
   type Data is record
      Root : MC_Posix.FD := -1;
      Reservation : Integer := -1;
      Limit, Deadline : Counter := 0;
      Mode : T.Operation := T.Install_Upgrade;
      Binding : Scope;
      Path : P.Byte_Strings.Bounded_String;
      Prior, Incoming : T.Image;
      Local_Mode, Local_UID, Local_GID : Word := 0;
      Incoming_Entry : P.Payload_Entry;
      Target_Effect, Backup_Effect : File_Effect;
      Prior_Original, Incoming_Original : Digest := Zero_Digest;
      Local, Backup : S.Snapshot;
      Proposal_Hash, Decision_Hash, Closure_Hash : Digest := Zero_Digest;
      Pending_Decision : T.Decision;
      Members, Sources : Objects.Set;
      Selected : Boolean := False;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Proposal) is
      Ignored : Interfaces.C.int;
   begin
      if Value.State /= null then
         S.Clear (Value.State.Local); S.Clear (Value.State.Backup);
         if Value.State.Root >= 0 then Ignored := MC_Posix.Close (Value.State.Root); end if;
         Free (Value.State);
      end if;
   end Clear;
   overriding procedure Finalize (Value : in out Proposal) is
   begin Clear (Value); end Finalize;
   function Address (Value : Proposal) return Digest is
     (if Value.State = null then Zero_Digest else Value.State.Proposal_Hash);
   function Pending (Value : Proposal) return T.Decision is
     (if Value.State = null then (others => <>) else Value.State.Pending_Decision);
   procedure Tick (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then (Now >= Deadline or else Deadline = Counter'Last) then Status := Stale; end if;
   end Tick;
   procedure Include (Value : in out Data; Hash : Digest) is
   begin
      if Hash /= Zero_Digest then Value.Members.Include (Hash); Value.Sources.Include (Hash); end if;
   end Include;
   procedure Verify_Members (Store : MC_Store.Store; Value : Data; Deadline : Counter; Status : out Outcome) is
      File : MC_FS.File;
   begin
      Status := Invalid_Input;
      if MC_Store.Native_Reservation (Store) /= Value.Reservation or else Value.Reservation < 0 then return; end if;
      for Hash of Value.Members loop
         Tick (Deadline, Status); exit when Status /= OK;
         MC_Store.Open_Object (Store, Hash, File, Status); MC_FS.Close (File); exit when Status /= OK;
      end loop;
      if Status = OK then Tick (Deadline, Status); end if;
   exception when others => MC_FS.Close (File); Status := Indeterminate;
   end Verify_Members;
   procedure Prepare (Store : in out MC_Store.Store; Root_FD : Integer;
      Root_ID, Transaction : Identity; Context : Digest; Mode : Operation;
      Path : String; Prior_Original, Incoming_Original : Digest;
      Limit, Deadline : Counter; Value : in out Proposal; Status : out Outcome) is
      Prior_Declaration, Incoming_Declaration : Digest := Zero_Digest;
      Remove_Flag : Boolean := False;
      Interrupted : exception;
      procedure Need is
      begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Source (Original : Digest; Is_Prior : Boolean; Image : out T.Image; Declaration : out Digest) is
         Inventory : D.Inventory; Payload : P.Inventory; Item : D.Declaration; Found : Boolean := False;
      begin
         Image := (others => <>); Declaration := Zero_Digest;
         if Original = Zero_Digest then return; end if;
         D.Inspect (Store, Original, Deadline, Inventory, Status); Need;
         Declaration := D.Declaration_Hash (Inventory); Include (Value.State.all, Original); Include (Value.State.all, Declaration);
         for I in 1 .. D.Count (Inventory) loop
            D.Read_Entry (Inventory, I, Item, Status); Need;
            if P.Byte_Strings.To_String (Item.Path) = Path then Found := True; exit; end if;
         end loop;
         if Is_Prior and then (not Found or else not Item.Present or else Item.Remove_On_Upgrade) then
            Status := Invalid_Input; raise Interrupted;
         end if;
         if Found and then Item.Present then
            if Item.Payload.Values.Kind /= P.Regular then Status := Unsupported; raise Interrupted; end if;
            Image := (T.Regular, Item.Payload.Values.Content);
            if not Is_Prior then Value.State.Incoming_Entry := Item.Payload; end if;
            Include (Value.State.all, Image.Content); Include (Value.State.all, Item.Payload.Values.Xattrs);
            Include (Value.State.all, Item.Payload.Values.ACLs);
         elsif not Found then
            -- Disappearing conffile declarations cannot silently authorize a
            -- conversion to an ordinary payload file at the same pathname.
            P.Stage (Store, Original, Deadline, Payload, Status); Need;
            if P.Find (Payload, Path (Path'First + 1 .. Path'Last)) /= 0 then Status := Unsupported; raise Interrupted; end if;
         end if;
         if not Is_Prior then Remove_Flag := Found and then Item.Remove_On_Upgrade; end if;
      end Source;
   begin
      Clear (Value); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Root_FD < 0 or else Root_ID = Zero_Identity or else Transaction = Zero_Identity or else Context = Zero_Digest
        or else Path'Length not in 2 .. P.Max_Name or else Path (Path'First) /= '/'
        or else MC_Store.Native_Reservation (Store) < 0 or else Limit > MC_Store.Max_Object_Size
        or else (Prior_Original = Zero_Digest and then Incoming_Original = Zero_Digest)
        or else (Mode /= Update and then (Prior_Original = Zero_Digest or else Incoming_Original /= Zero_Digest)) then return; end if;
      Tick (Deadline, Status); Need;
      Value.State := new Data; Value.State.Deadline := Deadline; Value.State.Limit := Limit;
      Value.State.Reservation := MC_Store.Native_Reservation (Store);
      Value.State.Binding := (Root_ID, Transaction, Context, Prior_Original, Incoming_Original);
      Value.State.Root := MC_Posix.Dup (Interfaces.C.int (Root_FD), 1030, 3);
      if Value.State.Root < 0 then Status := IO_Error; raise Interrupted; end if;
      Value.State.Path := P.Byte_Strings.To_Bounded_String (Path);
      Value.State.Prior_Original := Prior_Original; Value.State.Incoming_Original := Incoming_Original;
      S.Capture (Store, Integer (Value.State.Root), Path, Limit, Deadline, Value.State.Local, Status); Need;
      if S.Current (Value.State.Local).Kind = T.Regular then
         declare Observed : Pkg_Conffile_Observation.Observation; begin
            Pkg_Conffile_Observation.Load (Store, S.Metadata (Value.State.Local), Path, Deadline, Observed, Status); Need;
            Value.State.Local_Mode := Pkg_Conffile_Observation.Attributes (Observed).Node.Mode and 8#7777#;
            Value.State.Local_UID := Pkg_Conffile_Observation.Attributes (Observed).Node.UID;
            Value.State.Local_GID := Pkg_Conffile_Observation.Attributes (Observed).Node.GID;
         end;
      end if;
      Source (Prior_Original, True, Value.State.Prior, Prior_Declaration);
      Source (Incoming_Original, False, Value.State.Incoming, Incoming_Declaration);
      Value.State.Mode := (case Mode is when Update => (if Remove_Flag then T.Remove_On_Upgrade else T.Install_Upgrade),
                           when Remove => T.Remove_Package, when Purge => T.Purge_Package);
      T.Decide (Value.State.Mode, Prior_Original /= Zero_Digest, Value.State.Prior,
         S.Current (Value.State.Local), Value.State.Incoming, T.Unresolved, Value.State.Pending_Decision, Status); Need;
      Include (Value.State.all, S.Metadata (Value.State.Local)); Include (Value.State.all, S.Current (Value.State.Local).Content);
      declare Wire : Bytes (1 .. 344 + Path'Length) := (others => 0); begin
         Wire (1 .. 8) := (78, 73, 65, 67, 80, 82, 48, 49);
         Wire (9 .. 24) := Root_ID; Wire (25 .. 40) := Transaction; Wire (41 .. 72) := Context;
         Wire (73 .. 104) := Prior_Original; Wire (105 .. 136) := Incoming_Original;
         Wire (137 .. 168) := Prior_Declaration; Wire (169 .. 200) := Incoming_Declaration;
         Wire (201 .. 232) := S.Metadata (Value.State.Local); Wire (233 .. 264) := Value.State.Prior.Content;
         Wire (265 .. 296) := S.Current (Value.State.Local).Content; Wire (297 .. 328) := Value.State.Incoming.Content;
         Wire (329) := T.Operation'Pos (Value.State.Mode); Wire (330) := T.File_Kind'Pos (S.Current (Value.State.Local).Kind);
         Wire (331) := Boolean'Pos (Prior_Original /= Zero_Digest); Wire (332) := T.File_Kind'Pos (Value.State.Incoming.Kind);
         MC_Codec.Put64 (Wire, 333, Wide (Deadline)); MC_Codec.Put32 (Wire, 341, Word (Path'Length));
         for I in 1 .. Path'Length loop Wire (344 + I) := Character'Pos (Path (Path'First + I - 1)); end loop;
         MC_Store.Put (Store, Wire, Value.State.Proposal_Hash, Status); Need;
      end;
      Value.State.Members.Include (Value.State.Proposal_Hash);
      Verify_Members (Store, Value.State.all, Deadline, Status); Need;
      S.Recheck (Store, Value.State.Local, Deadline, Status); Need;
   exception
      when Interrupted => Clear (Value);
      when Storage_Error => Clear (Value); Status := Exhausted;
      when others => Clear (Value); Status := Indeterminate;
   end Prepare;
   procedure Recheck (Store : MC_Store.Store; Value : in out Proposal;
      Decision, Closure : Digest; Deadline : Counter; Status : out Outcome) is
      Bound : Counter;
   begin
      Status := Invalid_Input;
      if Value.State = null then return; end if;
      if not Value.State.Selected or else Decision = Zero_Digest or else Closure = Zero_Digest
        or else Decision /= Value.State.Decision_Hash or else Closure /= Value.State.Closure_Hash then Clear (Value); return; end if;
      Bound := Counter'Min (Deadline, Value.State.Deadline);
      Verify_Members (Store, Value.State.all, Bound, Status);
      if Status = OK then
         declare File : MC_FS.File; begin MC_Store.Open_Object (Store, Closure, File, Status); MC_FS.Close (File); end;
      end if;
      if Status = OK then S.Recheck (Store, Value.State.Local, Bound, Status); end if;
      if Status = OK and then S.Metadata (Value.State.Backup) /= Zero_Digest then
         S.Recheck (Store, Value.State.Backup, Bound, Status);
      end if;
      if Status = OK then Tick (Bound, Status); end if;
      if Status /= OK then Clear (Value); end if;
   exception when others => Clear (Value); Status := Indeterminate;
   end Recheck;
   procedure Read_Effects (Store : MC_Store.Store; Value : in out Proposal;
      Decision, Closure : Digest; Deadline : Counter;
      Target, Backup : out File_Effect; Status : out Outcome) is
   begin
      Target := (others => <>); Backup := (others => <>);
      Recheck (Store, Value, Decision, Closure, Deadline, Status);
      if Status = OK then Target := Value.State.Target_Effect; Backup := Value.State.Backup_Effect; end if;
   end Read_Effects;
   procedure Read_Scope (Store : MC_Store.Store; Value : in out Proposal;
      Decision, Closure : Digest; Deadline : Counter; Binding : out Scope; Status : out Outcome) is
   begin
      Binding := (others => <>);
      Recheck (Store, Value, Decision, Closure, Deadline, Status);
      if Status = OK then Binding := Value.State.Binding; end if;
   end Read_Scope;
   procedure Resolve (Store : in out MC_Store.Store; Value : in out Proposal;
      Expected : Digest; Selection : T.Choice; Backup_Path : String; Deadline : Counter;
      Decision, Closure : out Digest; Status : out Outcome) is
      Chosen : T.Decision; Bound : Counter; Next_Original : Digest := Zero_Digest;
      Interrupted : exception;
      procedure Need is
      begin if Status /= OK then raise Interrupted; end if; end Need;
      function Overlap (A, B : String) return Boolean is
        (A = B or else (A'Length < B'Length and then B (B'First .. B'First + A'Length - 1) = A
                       and then B (B'First + A'Length) = '/')
               or else (B'Length < A'Length and then A (A'First .. A'First + B'Length - 1) = B
                       and then A (A'First + B'Length) = '/'));
      procedure Describe (Destination : String; Content : Digest; Source : Attribute_Source; Effect : out File_Effect) is
      begin
         Effect := (others => <>); Effect.Path := P.Byte_Strings.To_Bounded_String (Destination);
         Effect.Content := Content; Effect.Source := Source;
         if Source = No_File then
            if Content /= Zero_Digest then Status := Corrupt; raise Interrupted; end if;
            return;
         end if;
         Effect.Source_Path := Value.State.Path;
         if Source = Local_Observation then
            if S.Current (Value.State.Local).Kind /= T.Regular or else Content /= S.Current (Value.State.Local).Content then
               Status := Corrupt; raise Interrupted;
            end if;
            Effect.Object := S.Metadata (Value.State.Local);
            Effect.Mode := Value.State.Local_Mode; Effect.UID := Value.State.Local_UID; Effect.GID := Value.State.Local_GID;
         else
            if Value.State.Incoming.Kind /= T.Regular or else Content /= Value.State.Incoming.Content then
               Status := Corrupt; raise Interrupted;
            end if;
            Effect.Object := Value.State.Incoming_Original;
            if S.Current (Value.State.Local).Kind = T.Regular then
               Effect.Permission_Override := S.Metadata (Value.State.Local);
               Effect.Mode := Value.State.Local_Mode; Effect.UID := Value.State.Local_UID; Effect.GID := Value.State.Local_GID;
            else
               Effect.Mode := Value.State.Incoming_Entry.Values.Mode;
               Effect.UID := Value.State.Incoming_Entry.Values.UID; Effect.GID := Value.State.Incoming_Entry.Values.GID;
            end if;
         end if;
      end Describe;
   begin
      Decision := Zero_Digest; Closure := Zero_Digest; Status := Invalid_Input;
      if Value.State = null then return; end if;
      if Value.State.Selected or else Expected = Zero_Digest or else Expected /= Value.State.Proposal_Hash then
         raise Interrupted;
      end if;
      Bound := Counter'Min (Deadline, Value.State.Deadline);
      S.Recheck (Store, Value.State.Local, Bound, Status); Need;
      if Value.State.Pending_Decision.Effect /= T.Require_Choice and then Selection /= T.Unresolved then
         Status := Invalid_Input; raise Interrupted;
      end if;
      T.Decide (Value.State.Mode, Value.State.Prior_Original /= Zero_Digest, Value.State.Prior,
         S.Current (Value.State.Local), Value.State.Incoming, Selection, Chosen, Status); Need;
      if Chosen.Effect = T.Require_Choice then Status := Conflict; raise Interrupted; end if;
      if Chosen.Backup /= T.No_Backup then
         if Backup_Path'Length not in 2 .. P.Max_Name or else Overlap (P.Byte_Strings.To_String (Value.State.Path), Backup_Path) then
            Status := Invalid_Input; raise Interrupted;
         end if;
         S.Capture (Store, Integer (Value.State.Root), Backup_Path, Value.State.Limit, Bound, Value.State.Backup, Status); Need;
         if S.Current (Value.State.Backup).Kind /= T.Missing then Status := Conflict; raise Interrupted; end if;
         Include (Value.State.all, S.Metadata (Value.State.Backup));
      elsif Backup_Path'Length /= 0 then Status := Invalid_Input; raise Interrupted;
      end if;
      if Chosen.Next_Vendor.Kind = T.Regular then
         Next_Original := (if Value.State.Incoming.Kind = T.Regular then Value.State.Incoming_Original else Value.State.Prior_Original);
      end if;
      Describe (P.Byte_Strings.To_String (Value.State.Path), Chosen.Content,
         (if Chosen.Content = Zero_Digest then No_File elsif Chosen.Effect = T.Replace then Vendor_Payload else Local_Observation), Value.State.Target_Effect);
      if Chosen.Backup /= T.No_Backup then
         Describe (Backup_Path, Chosen.Backup_Content,
            (if Chosen.Backup = T.Local_Backup then Local_Observation else Vendor_Payload), Value.State.Backup_Effect);
      end if;
      declare
         Wire : Bytes (1 .. 368 + Backup_Path'Length) := (others => 0);
         procedure Encode (At_Byte : Positive; Effect : File_Effect) is
         begin
            Wire (At_Byte) := Attribute_Source'Pos (Effect.Source);
            MC_Codec.Put32 (Wire, At_Byte + 4, Effect.Mode); MC_Codec.Put32 (Wire, At_Byte + 8, Effect.UID);
            MC_Codec.Put32 (Wire, At_Byte + 12, Effect.GID);
            Wire (At_Byte + 16 .. At_Byte + 47) := Effect.Object;
            Wire (At_Byte + 48 .. At_Byte + 79) := Effect.Permission_Override;
         end Encode;
      begin
         Wire (1 .. 8) := (78, 73, 65, 67, 67, 72, 48, 50); Wire (9 .. 40) := Expected;
         Wire (41) := T.Choice'Pos (Selection); Wire (42) := T.Action'Pos (Chosen.Effect);
         Wire (43) := T.Backup_Kind'Pos (Chosen.Backup); Wire (44) := T.File_Kind'Pos (Chosen.Next_Vendor.Kind);
         Wire (45 .. 76) := Chosen.Content; Wire (77 .. 108) := Chosen.Backup_Content;
         Wire (109 .. 140) := Chosen.Next_Vendor.Content; Wire (141 .. 172) := Next_Original;
         Wire (173 .. 204) := S.Metadata (Value.State.Backup); MC_Codec.Put32 (Wire, 205, Word (Backup_Path'Length));
         Encode (209, Value.State.Target_Effect); Encode (289, Value.State.Backup_Effect);
         for I in 1 .. Backup_Path'Length loop Wire (368 + I) := Character'Pos (Backup_Path (Backup_Path'First + I - 1)); end loop;
         MC_Store.Put (Store, Wire, Value.State.Decision_Hash, Status); Need;
      end;
      Value.State.Members.Include (Value.State.Decision_Hash);
      if Natural (Value.State.Members.Length) > 32 then Status := Exhausted; raise Interrupted; end if;
      Verify_Members (Store, Value.State.all, Bound, Status); Need;
      declare Wire : Bytes (1 .. 76 + 32 * Natural (Value.State.Members.Length)) := (others => 0); Pos : Natural := 76; begin
         Wire (1 .. 8) := (78, 73, 65, 67, 67, 70, 48, 49); Wire (9 .. 40) := Expected;
         Wire (41 .. 72) := Value.State.Decision_Hash; MC_Codec.Put32 (Wire, 73, Word (Value.State.Members.Length));
         for Hash of Value.State.Members loop Wire (Pos + 1 .. Pos + 32) := Hash; Pos := Pos + 32; end loop;
         MC_Store.Put (Store, Wire, Value.State.Closure_Hash, Status); Need;
      end;
      Value.State.Selected := True;
      Decision := Value.State.Decision_Hash; Closure := Value.State.Closure_Hash;
      Recheck (Store, Value, Decision, Closure, Bound, Status); Need;
   exception
      when Interrupted => Clear (Value); Decision := Zero_Digest; Closure := Zero_Digest;
      when Storage_Error => Clear (Value); Decision := Zero_Digest; Closure := Zero_Digest; Status := Exhausted;
      when others => Clear (Value); Decision := Zero_Digest; Closure := Zero_Digest; Status := Indeterminate;
   end Resolve;
   procedure Reobserve (Store : in out MC_Store.Store; Root_FD : Integer;
      Root_ID, Transaction : Identity; Context : Digest;
      Saved_Proposal, Saved_Decision, Saved_Closure : Digest; Limit, Deadline : Counter;
      Value : in out Proposal; Decision, Closure : out Digest; Status : out Outcome) is
      Old_Proposal, New_Proposal : Bytes (1 .. 344 + P.Max_Name);
      Old_Decision, New_Decision : Bytes (1 .. 368 + P.Max_Name);
      Retention : Bytes (1 .. 76 + 32 * 32);
      Proposal_Size, Decision_Size, Used, Count, Path_Length, Backup_Length : Natural;
      Members, Expected_Members : Objects.Set; Previous, Member : Digest := Zero_Digest;
      File : MC_FS.File; Current_Decision, Current_Closure : Digest;
      Mode : Operation;
      Interrupted : exception;
      procedure Need is begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Refuse (Reason : Outcome := Corrupt) is begin Status := Reason; raise Interrupted; end Refuse;
      procedure Read (Address : Digest; Wire : out Bytes; Length : out Natural) is
      begin
         Tick (Deadline, Status); Need;
         MC_Store.Read_Object (Store, Address, Wire, Length, Status); Need;
         if MC_SHA256.Hash (Wire (1 .. Length)) /= Address then Refuse; end if;
         Tick (Deadline, Status); Need;
      end Read;
      procedure Required (Address : Digest) is
      begin if Address /= Zero_Digest and then not Members.Contains (Address) then Refuse; end if; end Required;
      function Text (Wire : Bytes) return String is
         Result : String (1 .. Wire'Length);
      begin
         for I in Result'Range loop Result (I) := Character'Val (Wire (Wire'First + I - 1)); end loop;
         return Result;
      end Text;
   begin
      Clear (Value); Decision := Zero_Digest; Closure := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Root_FD < 0 or else Root_ID = Zero_Identity or else Transaction = Zero_Identity or else Context = Zero_Digest
         or else Saved_Proposal = Zero_Digest or else Saved_Decision = Zero_Digest or else Saved_Closure = Zero_Digest
         or else MC_Store.Native_Reservation (Store) < 0 or else Limit > MC_Store.Max_Object_Size then return; end if;
      Read (Saved_Closure, Retention, Used);
      if Used < 76 or else Retention (1 .. 8) /= Bytes'(78, 73, 65, 67, 67, 70, 48, 49)
         or else Retention (9 .. 40) /= Saved_Proposal or else Retention (41 .. 72) /= Saved_Decision
         or else MC_Codec.U32 (Retention, 73) not in 1 .. 32 then Refuse; end if;
      Count := Natural (MC_Codec.U32 (Retention, 73)); if Used /= 76 + 32 * Count then Refuse; end if;
      for I in 0 .. Count - 1 loop
         Member := Retention (77 + 32 * I .. 108 + 32 * I);
         if Member <= Previous then Refuse; end if; Previous := Member; Members.Insert (Member);
         Tick (Deadline, Status); Need; MC_Store.Open_Object (Store, Member, File, Status); Need; MC_FS.Close (File);
      end loop;
      Required (Saved_Proposal); Required (Saved_Decision);
      Read (Saved_Proposal, Old_Proposal, Proposal_Size); Read (Saved_Decision, Old_Decision, Decision_Size);
      if Proposal_Size < 344 or else Old_Proposal (1 .. 8) /= Bytes'(78, 73, 65, 67, 80, 82, 48, 49)
         or else Old_Proposal (9 .. 24) /= Root_ID or else Old_Proposal (25 .. 40) /= Transaction
         or else Old_Proposal (41 .. 72) /= Context or else Old_Proposal (329) > 3
         or else MC_Codec.U64 (Old_Proposal, 333) not in 1 .. Wide (Counter'Last - 1)
         or else MC_Codec.U32 (Old_Proposal, 341) not in 2 .. Word (P.Max_Name) then Refuse; end if;
      Path_Length := Natural (MC_Codec.U32 (Old_Proposal, 341));
      if Proposal_Size /= 344 + Path_Length then Refuse; end if;
      if Decision_Size < 368 or else Old_Decision (1 .. 8) /= Bytes'(78, 73, 65, 67, 67, 72, 48, 50)
         or else Old_Decision (9 .. 40) /= Saved_Proposal or else Old_Decision (41) > 2
         or else MC_Codec.U32 (Old_Decision, 205) > Word (P.Max_Name) then Refuse; end if;
      Backup_Length := Natural (MC_Codec.U32 (Old_Decision, 205));
      if Decision_Size /= 368 + Backup_Length then Refuse; end if;
      for I in 0 .. 7 loop Required (Old_Proposal (73 + 32 * I .. 104 + 32 * I)); end loop;
      for I in 0 .. 4 loop Required (Old_Decision (45 + 32 * I .. 76 + 32 * I)); end loop;
      for I in 0 .. 1 loop
         Required (Old_Decision (225 + 80 * I .. 256 + 80 * I));
         Required (Old_Decision (257 + 80 * I .. 288 + 80 * I));
      end loop;
      Mode := (case Old_Proposal (329) is when 0 | 3 => Update, when 1 => Remove, when others => Purge);
      Prepare (Store, Root_FD, Root_ID, Transaction, Context, Mode, Text (Old_Proposal (345 .. Proposal_Size)),
         Old_Proposal (73 .. 104), Old_Proposal (105 .. 136), Limit, Deadline, Value, Status); Need;
      Read (Address (Value), New_Proposal, Used);
      if Used /= Proposal_Size then Refuse (Stale); end if;
      -- Compare every recorded observation and original-derived field. Only the
      -- new observation lifetime differs; never rewrite the historical object.
      New_Proposal (333 .. 340) := Old_Proposal (333 .. 340);
      if New_Proposal (1 .. Used) /= Old_Proposal (1 .. Proposal_Size) then Refuse (Stale); end if;
      Resolve (Store, Value, Address (Value), T.Choice'Val (Old_Decision (41)),
         Text (Old_Decision (369 .. Decision_Size)), Deadline, Current_Decision, Current_Closure, Status); Need;
      Read (Current_Decision, New_Decision, Used);
      if Used /= Decision_Size then Refuse (Stale); end if;
      New_Decision (9 .. 40) := Saved_Proposal;
      if New_Decision (1 .. Used) /= Old_Decision (1 .. Decision_Size) then Refuse (Stale); end if;
      -- Keep sources separately: a content digest may legitimately also be a
      -- record digest. Removing session IDs from a flat set would lose that role.
      Expected_Members := Value.State.Sources;
      Expected_Members.Include (Saved_Proposal); Expected_Members.Include (Saved_Decision);
      if not Objects."=" (Members, Expected_Members) then Refuse; end if;
      Recheck (Store, Value, Current_Decision, Current_Closure, Deadline, Status); Need;
      Decision := Current_Decision; Closure := Current_Closure;
   exception
      when Interrupted => MC_FS.Close (File); Clear (Value); Decision := Zero_Digest; Closure := Zero_Digest;
      when Storage_Error => MC_FS.Close (File); Clear (Value); Decision := Zero_Digest; Closure := Zero_Digest; Status := Exhausted;
      when others => MC_FS.Close (File); Clear (Value); Decision := Zero_Digest; Closure := Zero_Digest; Status := Indeterminate;
   end Reobserve;
end Pkg_Conffile_Choice;
