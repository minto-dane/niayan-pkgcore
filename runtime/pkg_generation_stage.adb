-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation; with Interfaces.C; with System;
with MC_Clock;
with MC_Atomic; with MC_Dirents; with MC_FS; with MC_Hex; with MC_Log; with MC_Log_Format;
with MC_Posix; with MC_SHA256; with MC_Store; with MC_Text;
with Pkg_File_Engine; with Pkg_File_Plan; with Pkg_File_Replay;
with Pkg_Generation_Manifest; with Pkg_Image_Inspector; with Pkg_Recovery_Audit; with Pkg_Root_State;
package body Pkg_Generation_Stage with SPARK_Mode => Off is
   package GM renames Pkg_Generation_Manifest;
   use type Interfaces.C.int; use type Interfaces.C.unsigned; use type Interfaces.C.long;
   use type Wide; use type GM.Format_Kind;
   use type MC_FS.Entry_Info; use type MC_FS.Entry_Kind;
   use type Pkg_File_Plan.Kind; use type Pkg_File_Plan.Shape; use type Pkg_File_Replay.Direction;
   type Plan_Access is access Pkg_File_Plan.Plan;
   procedure Free is new Ada.Unchecked_Deallocation (Pkg_File_Plan.Plan, Plan_Access);
   procedure Time_Left (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      Status := Invalid_Input; if Deadline = Counter'Last then return; end if;
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Time_Left;
   procedure Gate (M : GM.Manifest; D : Digest; Phase : String; Deadline : Counter; Status : out Outcome) is
   begin
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      Authorize (D, Zero_Digest, Zero_Digest, M.Stage_ID, M.Transaction_ID,
                 M.Epoch, M.Fence, "stage:" & Phase, Status);
      if Status = OK then Time_Left (Deadline, Status); end if;
   end Gate;
   procedure Check_Content (Store : in out MC_Store.Store; M : GM.Manifest; Deadline : Counter; Status : out Outcome) is
   begin
      Time_Left (Deadline, Status);
      if Status = OK then GM.Check (Store, M, Status); end if;
      if Status = OK and then M.Format = GM.Native_V2 then GM.Check_Retention (Store, M, Deadline, Status); end if;
      if Status = OK then Time_Left (Deadline, Status); end if;
   end Check_Content;
   procedure Read_Binding (R : MC_FS.Root; Expected : Digest; M : out GM.Manifest; Status : out Outcome) is
      B : Bytes (1 .. GM.Max_Bytes); Used : Natural;
   begin
      M := (others => <>);
      MC_Atomic.Read (R, "generation.manifest", B, Used, Status);
      if Status /= OK then return; end if;
      if Expected = Zero_Digest or else MC_SHA256.Hash (B (1 .. Used)) /= Expected then Status := Denied; return; end if;
      GM.Decode (B (1 .. Used), M, Status);
   end Read_Binding;
   procedure Provision
     (Root_Path, State_Path, Store_Path : String; Encoded_Manifest : Bytes;
      Expected_Manifest : Digest; Deadline : Counter; Status : out Outcome) is
      M : GM.Manifest; Root, State : MC_FS.Root; Lock : MC_FS.File; Store : MC_Store.Store;
      Names : MC_Dirents.Listing; D : Digest;
      procedure Deny_Unused (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
         Epoch, Fence : Counter; Phase : String; Result : out Outcome) is
         pragma Unreferenced (Root_ID, Transaction_ID, Plan, Evidence, Epoch, Fence, Phase);
      begin Result := Denied; end Deny_Unused;
      package Engine is new Pkg_File_Engine (Deny_Unused);
      procedure Done is
      begin MC_Store.Close (Store); MC_FS.Close (Lock); MC_FS.Close (State); MC_FS.Close (Root); end Done;
   begin
      Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      if Encoded_Manifest'Length > GM.Max_Bytes or else Encoded_Manifest'Length < GM.Header_Size
        or else MC_SHA256.Hash (Encoded_Manifest) /= Expected_Manifest then Status := Denied; return; end if;
      GM.Decode (Encoded_Manifest, M, Status); if Status /= OK then return; end if;
      Gate (M, Expected_Manifest, "provision", Deadline, Status); if Status /= OK then return; end if;
      MC_Store.Open (Store_Path, Store, Status);
      if Status = OK then Check_Content (Store, M, Deadline, Status); end if;
      if Status = OK then MC_FS.Open_Root (Root_Path, Root, Status, Private_Only => True); end if;
      if Status = OK then MC_FS.List_Names (Root, "", Names, Status); end if;
      if Status = OK and then Names.Count /= 0 then Status := Conflict; end if;
      if Status = OK then MC_FS.Open_Root (State_Path, State, Status, Private_Only => True); end if;
      if Status = OK then MC_FS.List_Names (State, "", Names, Status); end if;
      if Status = OK and then Names.Count /= 0 then Status := Conflict; end if;
      if Status /= OK then Done; return; end if;
      declare A, B : MC_FS.Entry_Info; begin
         MC_FS.Root_Info (Root, A, Status);
         if Status = OK then MC_FS.Root_Info (State, B, Status); end if;
         if Status = OK and then A.Inode = B.Inode and then A.Mount_ID = B.Mount_ID then Status := Conflict; end if;
      end;
      if Status = OK then MC_FS.Create_New (State, "generation.lock", Lock, Status); end if;
      if Status = OK and then MC_Posix.Flock (Interfaces.C.int (MC_FS.Native (Lock)), MC_Posix.LOCK_EX_NB) /= 0
      then Status := Conflict; end if;
      if Status = OK then MC_FS.Sync (Lock, Status); end if;
      if Status = OK then MC_FS.Sync_Parent (State, "generation.lock", Status); end if;
      if Status = OK then MC_Store.Put (Store, Encoded_Manifest, D, Status); end if;
      if Status = OK and then D /= Expected_Manifest then Status := Corrupt; end if;
      if Status = OK then MC_Store.Pin (Store, M.Transaction_ID, Expected_Manifest, Status); end if;
      if Status = OK then MC_Atomic.Write (State, "generation.manifest", Encoded_Manifest, True, Status); end if;
      if Status = OK then Gate (M, Expected_Manifest, "provision-root", Deadline, Status); end if;
      if Status = OK then Engine.Provision (Root_Path, State_Path, M.Stage_ID, Status); end if;
      Done;
   exception when others => Done; Status := Indeterminate;
   end Provision;
   procedure Advance
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest;
      Completed_Batches : out Natural; Deadline : Counter; Status : out Outcome) is
      M : GM.Manifest; State, Private_Root : MC_FS.Root; Lock : MC_FS.File; Store : MC_Store.Store;
      P : Plan_Access := null; Used : Natural; Index : Natural := 0;
      Audit : Pkg_Recovery_Audit.Report;
      procedure Batch_Gate (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
         Epoch, Fence : Counter; Phase : String; Result : out Outcome) is
      begin
         Result := Denied;
         if Index = 0 or else Index > M.Count or else Root_ID /= M.Stage_ID
           or else Transaction_ID /= GM.Transaction (M, Index) or else Plan /= M.Batches (Index).Plan
           or else Epoch /= M.Epoch or else Fence /= M.Fence
           or else (Evidence /= Zero_Digest and then Evidence /= M.Batches (Index).Receipt)
           or else Phase in "restore" | "repair-journal" then return; end if;
         Time_Left (Deadline, Result); if Result /= OK then return; end if;
         Authorize (Expected_Manifest, Plan, Evidence, Root_ID, Transaction_ID,
                    Epoch, Fence, "stage:" & Phase, Result);
         if Result = OK then Time_Left (Deadline, Result); end if;
      end Batch_Gate;
      package Engine is new Pkg_File_Engine (Batch_Gate);
      C : Engine.Context;
      type Buffer_Access is access Bytes;
      procedure Free_Buffer is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      Buffer : Buffer_Access := null;
      procedure Done is
      begin
         Engine.Close (C); MC_Store.Close (Store); MC_FS.Close (Lock); MC_FS.Close (State); MC_FS.Close (Private_Root);
         Free (P); Free_Buffer (Buffer);
      end Done;
   begin
      Completed_Batches := 0; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      MC_FS.Open_Root (State_Path, State, Status, Private_Only => True);
      if Status = OK then MC_FS.Open_Locked (State, "generation.lock", Lock, Status, Create_If_Missing => False); end if;
      if Status = OK then Read_Binding (State, Expected_Manifest, M, Status); end if;
      if Status = OK then Gate (M, Expected_Manifest, "advance", Deadline, Status); end if;
      if Status = OK then MC_FS.Open_Root (Root_Path, Private_Root, Status, Private_Only => True); end if;
      if Status = OK then MC_Store.Open (Store_Path, Store, Status); end if;
      if Status = OK then MC_Store.Check_Pin (Store, M.Transaction_ID, Expected_Manifest, Status); end if;
      if Status = OK then Check_Content (Store, M, Deadline, Status); end if;
      MC_Store.Close (Store);
      if Status = OK then Engine.Open (Root_Path, State_Path, Store_Path, M.Stage_ID, C, Status); end if;
      if Status /= OK then Done; return; end if;
      if Engine.Generation (C) > Counter (M.Count) then Status := Corrupt; Done; return; end if;
      Index := Natural (Engine.Generation (C));
      if (Index = 0 and then Engine.Accepted_Plan (C) /= Zero_Digest)
        or else (Index > 0 and then Engine.Accepted_Plan (C) /= M.Batches (Index).Plan)
      then Status := Conflict; Done; return; end if;
      if Engine.Has_Active_Change (C) then
         Engine.Resume (C, Status); if Status /= OK then Done; return; end if;
         if Index > 0 and then Engine.Loaded_Plan (C) = M.Batches (Index).Plan then
            Engine.Reconcile_Terminal (C, Status);
            if Status = OK then Completed_Batches := Index; end if;
            Done; return;
         end if;
         if Index = M.Count then Status := Conflict; Done; return; end if;
         Index := Index + 1;
         if Engine.Loaded_Plan (C) /= M.Batches (Index).Plan then Status := Conflict; Done; return; end if;
         Pkg_Recovery_Audit.Inspect (State_Path, Store_Path, M.Batches (Index).Plan, Audit, Status);
         if Status /= OK then Done; return; end if;
         case Audit.Log_State.Phase is
            when Pkg_File_Replay.Forward | Pkg_File_Replay.Ready_To_Commit => Engine.Apply (C, Status);
            when Pkg_File_Replay.Commit_Pending => null;
            when others => Status := Conflict;
         end case;
      else
         if Index = M.Count then Completed_Batches := Index; Done; return; end if;
         -- The generation lock remains held while the inner engine releases the
         -- CAS lock to load the next bounded plan. The ordinary engine reacquires
         -- and independently verifies the same generation before any mutation.
         Engine.Close (C); Index := Index + 1;
         MC_Store.Open (Store_Path, Store, Status);
         P := new Pkg_File_Plan.Plan;
         if Status = OK then GM.Load_Plan (Store, M, Index, P.all, Status); end if;
         Buffer := new Bytes (1 .. Pkg_File_Plan.Max_Plan_Bytes);
         if Status = OK then Pkg_File_Plan.Encode (P.all, Buffer.all, Used, Status); end if;
         MC_Store.Close (Store);
         if Status = OK then Engine.Open (Root_Path, State_Path, Store_Path, M.Stage_ID, C, Status); end if;
         if Status = OK and then (Engine.Generation (C) /= Counter (Index - 1) or else Engine.Has_Active_Change (C))
         then Status := Conflict; end if;
         if Status = OK then Engine.Prepare (C, Buffer (1 .. Used), M.Batches (Index).Plan, Status); end if;
         if Status = OK then Engine.Apply (C, Status); end if;
      end if;
      if Status = OK then Engine.Commit (C, M.Batches (Index).Receipt, Status); end if;
      if Status = OK then Completed_Batches := Natural (Engine.Generation (C)); end if;
      Done;
   exception when others => Done; Completed_Batches := 0; Status := Indeterminate;
   end Advance;
   procedure Count_Children (R : MC_FS.Root; Path : String; Count : out Natural; Status : out Outcome) is
      function Getdents64 (F : Interfaces.C.int; B : System.Address; N : Interfaces.C.size_t)
         return Interfaces.C.long with Import, Convention => C, External_Name => "getdents64";
      F : MC_FS.File; Before, Opened, After : MC_FS.Entry_Info;
      B : aliased Bytes (1 .. 8_192); N : Interfaces.C.long; Calls : Natural := 0;
      Names : MC_Dirents.Listing;
   begin
      Count := 0; MC_FS.Stat (R, Path, Before, Status);
      if Status = OK and then Before.Kind /= MC_FS.Directory then Status := Conflict; end if;
      if Status = OK then MC_FS.Open_Read (R, Path, F, Status); end if;
      if Status = OK then MC_FS.Info (F, Opened, Status); end if;
      if Status = OK and then Opened /= Before then Status := Conflict; end if;
      if Status /= OK then MC_FS.Close (F); return; end if;
      loop
         if Calls = GM.Max_Entries + 2 then Status := Exhausted; exit; end if;
         Calls := Calls + 1; N := Getdents64 (Interfaces.C.int (MC_FS.Native (F)), B'Address, B'Length);
         if N < 0 then
            if MC_Posix.Errno_Location.all /= MC_Posix.EINTR then Status := IO_Error; exit; end if;
         elsif N = 0 then exit;
         elsif N > Interfaces.C.long (B'Length) then Status := Corrupt; exit;
         else
            -- A fresh bounded page, at most 341 minimum-size Linux dirents.
            -- The checked parser skips dot entries; d_type/cookies are not trusted.
            Names := (others => <>); MC_Dirents.Append_Linux64_LE (B (1 .. Natural (N)), Names, Status);
            exit when Status /= OK;
            if Count > GM.Max_Entries - Names.Count then Status := Exhausted; exit; end if;
            Count := Count + Names.Count;
         end if;
      end loop;
      if Status = OK then MC_FS.Info (F, After, Status); end if;
      if Status = OK and then After /= Before then Status := Conflict; end if;
      MC_FS.Close (F);
      if Status = OK then MC_FS.Stat (R, Path, After, Status); end if;
      if Status = OK and then After /= Before then Status := Conflict; end if;
   exception when others => MC_FS.Close (F); Status := Indeterminate;
   end Count_Children;
   procedure Close (C : in out Verified_Generation) is
   begin
      MC_FS.Close (C.Root_Lock); MC_FS.Close (C.Lock);
      MC_FS.Close (C.State); MC_FS.Close (C.Root);
      C.Verified := False; C.Bound_Manifest := Zero_Digest;
   end Close;
   function Held (C : Verified_Generation) return Boolean is (C.Verified);
   function Manifest (C : Verified_Generation) return Digest is (C.Bound_Manifest);
   procedure Verify_And_Hold
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest;
      C : in out Verified_Generation; Deadline : Counter; Status : out Outcome) is
      M : GM.Manifest; Store : MC_Store.Store;
      Root : MC_FS.Root renames C.Root;
      State : MC_FS.Root renames C.State;
      Lock : MC_FS.File renames C.Lock;
      Root_Lock : MC_FS.File renames C.Root_Lock;
      P : Plan_Access := null; Names : MC_Dirents.Listing; RS : Pkg_Root_State.State;
      State_Bytes : Pkg_Root_State.Frame; Marker : Bytes (1 .. 16); Used, Children, Total : Natural := 0;
      Shape : Pkg_File_Plan.Shape; Read_Bytes : Counter; Journal : MC_Log.Journal;
      E : MC_Log_Format.Log_Entry; V : Pkg_File_Replay.View; Binding : Pkg_File_Replay.Binding;
      procedure Done is
      begin
         MC_Log.Close (Journal); MC_Store.Close (Store); Free (P);
         if not C.Verified then Close (C); end if;
      end Done;
   begin
      Status := Conflict; if C.Verified then return; end if;
      Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Time_Left (Deadline, Status); if Status /= OK then return; end if;
      MC_FS.Open_Root (State_Path, State, Status, Private_Only => True);
      if Status = OK then MC_FS.Open_Locked (State, "generation.lock", Lock, Status, Create_If_Missing => False); end if;
      if Status = OK then Read_Binding (State, Expected_Manifest, M, Status); end if;
      if Status = OK then Gate (M, Expected_Manifest, "inspect", Deadline, Status); end if;
      if Status = OK then MC_FS.Open_Locked (State, "root.lock", Root_Lock, Status, Create_If_Missing => False); end if;
      if Status = OK then MC_FS.Open_Root (Root_Path, Root, Status, Private_Only => True); end if;
      if Status = OK then MC_Atomic.Read (Root, ".mission/root.id", Marker, Used, Status); end if;
      if Status = OK and then (Used /= 16 or else Marker /= M.Stage_ID) then Status := Conflict; end if;
      if Status = OK then MC_Atomic.Read (State, "root.state", State_Bytes, Used, Status); end if;
      if Status = OK and then Used /= State_Bytes'Length then Status := Corrupt; end if;
      if Status = OK then Pkg_Root_State.Decode (State_Bytes, RS, Status); end if;
      if Status = OK and then (RS.Root_ID /= M.Stage_ID or else RS.Generation /= Counter (M.Count)
        or else RS.Active_Transaction /= Zero_Identity or else RS.Active_Plan /= Zero_Digest
        or else RS.Accepted_Plan /= M.Batches (M.Count).Plan or else RS.Package_Set /= M.Catalog)
      then Status := Conflict; end if;
      if Status = OK then MC_Store.Open (Store_Path, Store, Status); end if;
      if Status = OK then MC_Store.Check_Pin (Store, M.Transaction_ID, Expected_Manifest, Status); end if;
      if Status = OK then Check_Content (Store, M, Deadline, Status); end if;
      if Status = OK then MC_FS.List_Names (Root, "", Names, Status); end if;
      if Status = OK and then (Names.Count /= 3 or else MC_Dirents.Image (Names.Names (1)) /= ".mission"
        or else MC_Dirents.Image (Names.Names (2)) /= "catalog" or else MC_Dirents.Image (Names.Names (3)) /= "tree")
      then Status := Conflict; end if;
      if Status = OK then MC_FS.List_Names (Root, ".mission", Names, Status); end if;
      if Status = OK and then (Names.Count /= 1 or else MC_Dirents.Image (Names.Names (1)) /= "root.id")
      then Status := Conflict; end if;
      if Status /= OK then Done; return; end if;
      Total := 2; P := new Pkg_File_Plan.Plan;
      for I in 1 .. M.Count loop
         Gate (M, Expected_Manifest, "inspect-batch", Deadline, Status); exit when Status /= OK;
         GM.Load_Plan (Store, M, I, P.all, Status); exit when Status /= OK;
         MC_Store.Check_Pin (Store, P.Transaction_ID, M.Batches (I).Plan, Status); exit when Status /= OK;
         MC_Log.Open (State, "tx-" & MC_Hex.Encode (P.Transaction_ID) & ".log", M.Stage_ID,
                      Journal, Status, Create_If_Missing => False); exit when Status /= OK;
         Binding := (M.Stage_ID, P.Transaction_ID, M.Batches (I).Plan, M.Epoch, M.Fence, Counter (I), P.Count);
         V := (others => <>);
         for J in 1 .. MC_Log.Length (Journal) loop
            MC_Log.Read (Journal, J, E, Status); exit when Status /= OK;
            Pkg_File_Replay.Consume (Binding, E, V, Status); exit when Status /= OK;
         end loop;
         MC_Log.Close (Journal); exit when Status /= OK;
         if V.Phase /= Pkg_File_Replay.Forward_Final or else V.Receipt /= M.Batches (I).Receipt
         then Status := Conflict; exit; end if;
         for J in 1 .. P.Count loop
            declare Path : constant String := MC_Text.Image (P.Changes (J).Path); begin
               Pkg_Image_Inspector.Inspect (Root, Path, MC_Store.Max_Object_Size, Shape, Read_Bytes, Status);
               exit when Status /= OK;
               if Shape /= P.Changes (J).After then Status := Conflict; exit; end if;
               if Shape.Node_Kind = Pkg_File_Plan.Directory then
                  Count_Children (Root, Path, Children, Status); exit when Status /= OK;
                  if Children > M.Entries - Total then Status := Conflict; exit; end if;
                  Total := Total + Children;
               end if;
            end;
         end loop;
         exit when Status /= OK;
      end loop;
      if Status = OK and then Total /= M.Entries then Status := Conflict; end if;
      if Status = OK then Gate (M, Expected_Manifest, "inspected", Deadline, Status); end if;
      if Status = OK then C.Verified := True; C.Bound_Manifest := Expected_Manifest; end if;
      Done;
   exception when others => Close (C); Done; Status := Indeterminate;
   end Verify_And_Hold;
   procedure Inspect
     (Root_Path, State_Path, Store_Path : String; Expected_Manifest : Digest; Deadline : Counter;
      Status : out Outcome) is
      C : Verified_Generation;
   begin
      Verify_And_Hold (Root_Path, State_Path, Store_Path, Expected_Manifest, C, Deadline, Status);
      Close (C);
   exception when others => Close (C); Status := Indeterminate;
   end Inspect;
end Pkg_Generation_Stage;
