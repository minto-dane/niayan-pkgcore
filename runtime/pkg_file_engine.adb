-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation;
with MC_Atomic; with MC_Text; with MC_SHA256; with MC_Hex; with MC_Log_Format;
with MC_Posix; with MC_Codec; with Pkg_File_Replay;
package body Pkg_File_Engine with SPARK_Mode => Off is
   use type MC_FS.Entry_Info;
   use Pkg_File_Plan; use type MC_FS.Entry_Kind; use type Word;
   Prepared : constant := 1; Apply_Intent : constant := 2; Apply_Done : constant := 3;
   Applied : constant := 4; Commit_Intent : constant := 5; Committed : constant := 6;
   Restore_Intent : constant := 7; Restore_Done : constant := 8; Restored : constant := 9;
   Tail_Repaired : constant := 10;
   procedure Free is new Ada.Unchecked_Deallocation(Pkg_File_Plan.Plan,Plan_Access);
   function Image_Of(N : Natural) return String is
      S : constant String:=Natural'Image(N);
   begin return S(S'First+1..S'Last); end;
   procedure Guard(C : Context; Phase : String; Status : out Outcome; Evidence : Digest:=Zero_Digest) is
   begin
      Status:=Invalid_Input;
      if not C.Opened or else C.Poisoned or else C.Plan=null then return; end if;
      Authorize(C.Root_State.Root_ID,C.Plan.Transaction_ID,C.Plan_Digest,Evidence,
                C.Plan.Epoch,C.Plan.Fence,Phase,Status);
   end Guard;
   procedure Persist_State(C : in out Context; Status : out Outcome) is
      B : constant Pkg_Root_State.Frame:=Pkg_Root_State.Encode(C.Root_State);
   begin
      MC_Atomic.Write(C.State_Directory,"root.state",B,False,Status);
      if Status/=OK then C.Poisoned:=True; Status:=Indeterminate; end if;
   end Persist_State;
   procedure Emit(C : in out Context; Kind : Natural; Index : Natural; Object : Digest; Status : out Outcome) is
      E : MC_Log_Format.Log_Entry;
   begin
      E.Kind:=Kind; E.Root_ID:=C.Root_State.Root_ID; E.Operation_ID:=C.Plan.Transaction_ID;
      E.Epoch:=C.Plan.Epoch; E.Token:=C.Plan.Fence; E.Index:=Counter(Index);
      E.Generation:=C.Plan.Target_Generation; E.Object:=Object;
      MC_Log.Append(C.Journal,E,Status);
      if Status/=OK then C.Poisoned:=True; Status:=Indeterminate; end if;
   end Emit;
   procedure Provision(Root_Path, State_Path : String; Root_ID : Identity; Status : out Outcome) is
      R, S : MC_FS.Root; L : MC_FS.File; State : Pkg_Root_State.State;
      V : MC_FS.Entry_Info; B : Bytes(1..16); Used : Natural;
   begin
      Status:=Invalid_Input; if Root_ID=Zero_Identity then return; end if;
      MC_FS.Open_Root(Root_Path,R,Status); if Status/=OK then return; end if;
      MC_FS.Open_Root(State_Path,S,Status,Private_Only=>True);
      if Status/=OK then MC_FS.Close(R); return; end if;
      MC_FS.Open_Locked(S,"root.lock",L,Status);
      if Status=OK then
         MC_FS.Stat(R,".mission",V,Status);
         if Status=OK and then V.Kind=MC_FS.Absent then MC_FS.Make_Directory(R,".mission",Status);
         elsif Status=OK and then (V.Kind/=MC_FS.Directory or else V.Mode/=8#700#) then Status:=Denied; end if;
      end if;
      if Status=OK then
         MC_FS.Stat(R,".mission/root.id",V,Status);
         if Status=OK and then V.Kind=MC_FS.Absent then MC_Atomic.Write(R,".mission/root.id",Root_ID,True,Status);
         elsif Status=OK then
            MC_Atomic.Read(R,".mission/root.id",B,Used,Status);
            if Status=OK and then (Used/=16 or else B/=Root_ID) then Status:=Conflict; end if;
         end if;
      end if;
      if Status=OK then
         State.Root_ID:=Root_ID;
         -- Refuse re-provisioning existing state. Never reset generation/replay state.
         MC_Atomic.Write(S,"root.state",Pkg_Root_State.Encode(State),True,Status);
      end if;
      MC_FS.Close(L); MC_FS.Close(S); MC_FS.Close(R);
   exception when others => MC_FS.Close(L); MC_FS.Close(S); MC_FS.Close(R); Status:=Indeterminate;
   end Provision;
   procedure Open(Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
                  C : in out Context; Status : out Outcome) is
      B : Pkg_Root_State.Frame; Marker : Bytes(1..16); Used : Natural;
   begin
      Status:=Conflict; if C.Opened then return; end if;
      MC_FS.Open_Root(Root_Path,C.Root,Status); if Status/=OK then return; end if;
      MC_FS.Open_Root(State_Path,C.State_Directory,Status,Private_Only=>True);
      if Status=OK then MC_FS.Open_Locked(C.State_Directory,"root.lock",C.Root_Lock,Status,Create_If_Missing=>False); end if;
      if Status=OK then MC_Atomic.Read(C.Root,".mission/root.id",Marker,Used,Status); end if;
      if Status=OK and then (Used/=16 or else Marker/=Root_ID) then Status:=Denied; end if;
      if Status=OK then MC_Atomic.Read(C.State_Directory,"root.state",B,Used,Status); end if;
      if Status=OK and then Used/=B'Length then Status:=Corrupt; end if;
      if Status=OK then Pkg_Root_State.Decode(B,C.Root_State,Status); end if;
      if Status=OK and then C.Root_State.Root_ID/=Root_ID then Status:=Denied; end if;
      if Status=OK then MC_Store.Open(Store_Path,C.Store,Status); end if;
      if Status/=OK then Close(C); return; end if;
      C.Opened:=True; C.Poisoned:=False;
   exception when others => Close(C); Status:=IO_Error;
   end Open;
   procedure Capture(C : in out Context; Path : String; Save : Boolean;
                      S : out Shape; Status : out Outcome) is
      V, Opened, Observed_After : MC_FS.Entry_Info; F : MC_FS.File; B : Bytes(1..MC_FS.Max_Xattr_Bytes);
      Used : Natural; Link : MC_Text.Value; D : Digest; Length : Counter;
   begin
      S:=(others=><>); MC_FS.Stat(C.Root,Path,V,Status);
      if Status=Stale and then C.Plan/=null then
         -- A not-yet-created planned parent makes its absent descendants absent.
         -- Do not turn arbitrary lookup failures into absent preimages.
         for I in 1..C.Plan.Count loop
            declare A : constant String:=MC_Text.Image(C.Plan.Changes(I).Path); Parent_Info : MC_FS.Entry_Info; Q : Outcome; begin
               if C.Plan.Changes(I).Before.Node_Kind=Absent and then C.Plan.Changes(I).After.Node_Kind=Directory
                 and then A'Length<Path'Length and then Path(Path'First..Path'First+A'Length-1)=A
                 and then Path(Path'First+A'Length)='/' then
                  MC_FS.Stat(C.Root,A,Parent_Info,Q);
                  if Q=OK and then Parent_Info.Kind=MC_FS.Absent then Status:=OK; return; end if;
               end if;
            end;
         end loop;
      end if;
      if Status/=OK then return; end if;
      case V.Kind is
         when MC_FS.Absent => return;
         when MC_FS.Regular => S.Node_Kind:=Regular;
         when MC_FS.Directory => S.Node_Kind:=Directory;
         when MC_FS.Symbolic_Link => S.Node_Kind:=Symbolic_Link;
         when others => Status:=Unsupported; return;
      end case;
      S.Mode:=V.Mode; S.UID:=V.UID; S.GID:=V.GID;
      if V.Kind=MC_FS.Symbolic_Link then
         MC_FS.Read_Link(C.Root,Path,Link,Status); if Status/=OK then return; end if;
         declare Text : constant String:=MC_Text.Image(Link); Bytes_Of_Link : Bytes(1..Text'Length); begin
            for I in Text'Range loop Bytes_Of_Link(I):=Byte(Character'Pos(Text(I))); end loop;
            S.Size:=Counter(Text'Length);
            if Save then MC_Store.Put(C.Store,Bytes_Of_Link,S.Content,Status);
            else S.Content:=MC_SHA256.Hash(Bytes_Of_Link); end if;
         end;
         if Status=OK then MC_FS.Get_Link_Xattrs(C.Root,Path,B,Used,Status); end if;
      else
         MC_FS.Open_Read(C.Root,Path,F,Status); if Status/=OK then return; end if;
         MC_FS.Info(F,Opened,Status);
         if Status=OK and then Opened/=V then Status:=Stale; end if;
         if Status/=OK then MC_FS.Close(F); return; end if;
         if V.Kind=MC_FS.Regular then
            S.Size:=V.Size; S.Mtime_Sec:=V.Mtime_Sec; S.Mtime_Nsec:=V.Mtime_Nsec;
            if Save then MC_Store.Import_File(C.Store,F,MC_Store.Max_Object_Size,S.Content,Status);
            else MC_FS.Hash(F,MC_Store.Max_Object_Size,D,Length,Status); S.Content:=D; end if;
         end if;
         if Status=OK then MC_FS.Get_Xattrs(F,B,Used,Status); end if;
         if Status=OK then MC_FS.Info(F,Observed_After,Status); end if;
         if Status=OK and then Observed_After/=Opened then Status:=Stale; end if;
         MC_FS.Close(F);
      end if;
      if Status/=OK then return; end if;
      if Save then MC_Store.Put(C.Store,B(1..Used),S.Xattrs,Status);
      else S.Xattrs:=MC_SHA256.Hash(B(1..Used)); end if;
      if Status=OK then MC_FS.Stat(C.Root,Path,Observed_After,Status); end if;
      if Status=OK and then Observed_After/=V then Status:=Stale; end if;
      -- No persisted preimage may combine attributes of one pathname target with
      -- bytes/xattrs from another. CAS objects already saved on a stale read are
      -- unreferenced evidence, never an accepted plan or a reason to overwrite.
      if Status=OK and then not Valid(S) then Status:=Unsupported; end if;
   exception when others => MC_FS.Close(F); Status:=IO_Error;
   end Capture;
   procedure Check_Objects(C : in out Context; S : Shape; Status : out Outcome) is
      F : MC_FS.File; V : MC_FS.Entry_Info;
   begin
      Status:=OK; if S.Node_Kind=Absent then return; end if;
      MC_Store.Open_Object(C.Store,S.Xattrs,F,Status); MC_FS.Close(F); if Status/=OK then return; end if;
      if S.Node_Kind in Regular | Symbolic_Link then
         MC_Store.Open_Object(C.Store,S.Content,F,Status);
         if Status=OK then MC_FS.Info(F,V,Status); end if; MC_FS.Close(F);
         if Status=OK and then V.Size/=S.Size then Status:=Corrupt; end if;
      end if;
   end Check_Objects;
   use Pkg_File_Replay;
   subtype Log_View is Pkg_File_Replay.View;
   function Replay_Binding(C : Context) return Pkg_File_Replay.Binding is
     (Root_ID => C.Plan.Root_ID, Transaction_ID => C.Plan.Transaction_ID,
      Plan_Digest => C.Plan_Digest, Epoch => C.Plan.Epoch, Fence => C.Plan.Fence,
      Target_Generation => C.Plan.Target_Generation, Changes => C.Plan.Count);
   procedure Read_Log(C : Context; V : out Log_View; Status : out Outcome);
   procedure Prepare(C : in out Context; Encoded_Plan : Bytes;
                     Expected_Digest : Digest; Status : out Outcome) is
      Seen : Shape; Stored : Digest; Orphan : MC_Log_Format.Log_Entry;
   begin
      Status:=Conflict;
      if not C.Opened or else C.Poisoned or else C.Root_State.Active_Transaction/=Zero_Identity
        or else C.Plan/=null then return; end if;
      if MC_SHA256.Hash(Encoded_Plan)/=Expected_Digest then Status:=Denied; return; end if;
      C.Plan:=new Pkg_File_Plan.Plan; Pkg_File_Plan.Decode(Encoded_Plan,C.Plan.all,Status);
      if Status/=OK then Free(C.Plan); return; end if;
      C.Plan_Digest:=Expected_Digest;
      if C.Plan.Root_ID/=C.Root_State.Root_ID or else C.Plan.Base_Generation/=C.Root_State.Generation then
         Status:=Stale; Free(C.Plan); return;
      end if;
      Guard(C,"prepare",Status); if Status/=OK then Free(C.Plan); return; end if;
      MC_Store.Put(C.Store,Encoded_Plan,Stored,Status);
      if Status/=OK or else Stored/=Expected_Digest then Free(C.Plan); Status:=Corrupt; return; end if;
      for I in 1..C.Plan.Count loop
         Guard(C,"capture",Status); exit when Status/=OK;
         Capture(C,MC_Text.Image(C.Plan.Changes(I).Path),True,Seen,Status); exit when Status/=OK;
         if Seen/=C.Plan.Changes(I).Before then Status:=Conflict; exit; end if;
         Check_Objects(C,C.Plan.Changes(I).After,Status); exit when Status/=OK;
      end loop;
      if Status/=OK then Free(C.Plan); return; end if;
      MC_Store.Pin(C.Store,C.Plan.Transaction_ID,C.Plan_Digest,Status);
      if Status/=OK then Free(C.Plan); return; end if;
      MC_Log.Open(C.State_Directory,"tx-" & MC_Hex.Encode(C.Plan.Transaction_ID) & ".log",C.Root_State.Root_ID,C.Journal,Status);
      if Status/=OK then Free(C.Plan); return; end if;
      if MC_Log.Length(C.Journal)=0 then
         Emit(C,Prepared,0,C.Plan_Digest,Status); if Status/=OK then return; end if;
      elsif MC_Log.Length(C.Journal)=1 then
         -- A crash after Prepared but before root.state published causes no host
         -- effect. All preimages have just been recaptured above before adoption.
         MC_Log.Read(C.Journal,1,Orphan,Status);
         if Status/=OK or else Orphan.Kind/=Prepared or else Orphan.Object/=C.Plan_Digest
           or else Orphan.Operation_ID/=C.Plan.Transaction_ID or else Orphan.Epoch/=C.Plan.Epoch
           or else Orphan.Token/=C.Plan.Fence or else Orphan.Generation/=C.Plan.Target_Generation
         then MC_Log.Close(C.Journal); Free(C.Plan); Status:=Conflict; return; end if;
      else MC_Log.Close(C.Journal); Free(C.Plan); Status:=Conflict; return; end if;
      C.Root_State.Active_Transaction:=C.Plan.Transaction_ID; C.Root_State.Active_Plan:=C.Plan_Digest;
      Persist_State(C,Status);
   exception when others => C.Poisoned:=True; Status:=Indeterminate;
   end Prepare;
   procedure Read_Log(C : Context; V : out Log_View; Status : out Outcome) is
      E : MC_Log_Format.Log_Entry;
   begin
      V:=(others=><>); Status:=Corrupt;
      if C.Plan=null or else MC_Log.Length(C.Journal)=0 then return; end if;
      for I in 1..MC_Log.Length(C.Journal) loop
         MC_Log.Read(C.Journal,I,E,Status); if Status/=OK then return; end if;
         Pkg_File_Replay.Consume(Replay_Binding(C),E,V,Status);
         if Status/=OK then return; end if;
      end loop;
      Status:=OK;
   end Read_Log;
   procedure Validate_Log(C : Context; Status : out Outcome) is
      V : Log_View;
   begin Read_Log(C,V,Status); end Validate_Log;
   procedure Load_Plan(C : in out Context; Expected : Digest; Status : out Outcome) is
      type Buffer_Access is access Bytes;
      procedure Free_Buffer is new Ada.Unchecked_Deallocation(Bytes,Buffer_Access);
      B : Buffer_Access := null; Used : Natural;
   begin
      B:=new Bytes(1..Max_Plan_Bytes);
      MC_Store.Read_Object(C.Store,Expected,B.all,Used,Status);
      if Status=OK then
         C.Plan:=new Plan; Decode(B(1..Used),C.Plan.all,Status);
         if Status/=OK then Free(C.Plan); end if;
      end if;
      Free_Buffer(B);
   exception when others => Free_Buffer(B); raise;
   end Load_Plan;
   procedure Resume(C : in out Context; Status : out Outcome) is
      Pin_Status : Outcome;
   begin
      Status:=Invalid_Input;
      if not C.Opened or else C.Poisoned or else C.Plan/=null or else C.Root_State.Active_Transaction=Zero_Identity then return; end if;
      C.Plan_Digest:=C.Root_State.Active_Plan;
      Load_Plan(C,C.Plan_Digest,Status); if Status/=OK then return; end if;
      if C.Plan.Root_ID/=C.Root_State.Root_ID or else C.Plan.Transaction_ID/=C.Root_State.Active_Transaction
        or else (C.Root_State.Generation/=C.Plan.Base_Generation and then
          (C.Root_State.Generation/=C.Plan.Target_Generation or else C.Root_State.Accepted_Plan/=C.Plan_Digest
           or else C.Root_State.Package_Set/=C.Plan.Package_Set)) then Status:=Conflict; return; end if;
      MC_Store.Check_Pin(C.Store,C.Plan.Transaction_ID,C.Plan_Digest,Pin_Status);
      if Pin_Status/=OK then Status:=Pin_Status; return; end if;
      MC_Log.Open(C.State_Directory,"tx-" & MC_Hex.Encode(C.Plan.Transaction_ID) & ".log",C.Root_State.Root_ID,C.Journal,Status,Create_If_Missing=>False);
      if Status=OK or else (Status=Indeterminate and then MC_Log.Has_Torn_Tail(C.Journal)) then
         Validate_Log(C,Pin_Status); if Pin_Status/=OK then Status:=Pin_Status; end if;
      end if;
   exception when others => C.Poisoned:=True; Status:=Indeterminate;
   end Resume;
   procedure Resume_Recorded(C : in out Context; Expected_Plan : Digest; Status : out Outcome) is
      V : Log_View; Other : Outcome;
   begin
      if C.Root_State.Active_Transaction/=Zero_Identity then
         Resume(C,Status);
         if C.Plan_Digest/=Expected_Plan then Status:=Denied; end if;
         return;
      end if;
      Status:=Invalid_Input;
      if not C.Opened or else C.Poisoned or else C.Plan/=null or else Expected_Plan=Zero_Digest then return; end if;
      Load_Plan(C,Expected_Plan,Status); if Status/=OK then return; end if;
      C.Plan_Digest:=Expected_Plan;
      if C.Plan.Root_ID/=C.Root_State.Root_ID then Status:=Denied; return; end if;
      MC_Store.Check_Pin(C.Store,C.Plan.Transaction_ID,Expected_Plan,Status); if Status/=OK then return; end if;
      MC_Log.Open(C.State_Directory,"tx-" & MC_Hex.Encode(C.Plan.Transaction_ID) & ".log",C.Root_State.Root_ID,C.Journal,Status,Create_If_Missing=>False);
      if Status/=OK then return; end if;
      Read_Log(C,V,Other); if Other/=OK then Status:=Other; return; end if;
      if C.Root_State.Generation=C.Plan.Target_Generation and then C.Root_State.Accepted_Plan=Expected_Plan
        and then C.Root_State.Package_Set=C.Plan.Package_Set and then V.Phase=Forward_Final then Status:=OK;
      elsif C.Root_State.Generation=C.Plan.Base_Generation and then V.Phase=Reverse_Final then Status:=OK;
      else Status:=Conflict; end if;
      -- Loaded for re-observation/terminal receipt reconciliation only. The normal
      -- effect state machine rejects both terminal directions. No new generation.
   exception when others => C.Poisoned:=True; Status:=Indeterminate;
   end Resume_Recorded;
   function Loaded_Plan(C : Context) return Digest is (C.Plan_Digest);
   procedure Inspect(C : in out Context; Image : out Actual_Image; Status : out Outcome) is
      S : Shape; Before, After : Boolean:=True; V : Log_View;
   begin
      Image:=Unknown_Objects; Status:=Invalid_Input;
      if not C.Opened or else C.Plan=null then return; end if;
      Read_Log(C,V,Status); if Status/=OK then return; end if;
      for I in 1..C.Plan.Count loop
         Capture(C,MC_Text.Image(C.Plan.Changes(I).Path),False,S,Status); if Status/=OK then return; end if;
         Before:=Before and S=C.Plan.Changes(I).Before; After:=After and S=C.Plan.Changes(I).After;
         if not Pkg_File_Replay.Image_Allowed(Replay_Binding(C),V,I,
              S=C.Plan.Changes(I).Before,S=C.Plan.Changes(I).After)
         then Status:=Conflict; return; end if;
      end loop;
      Image:=(if Before then All_Before elsif After then All_After else Mixed_Known); Status:=OK;
   end Inspect;
   function Safe_Link(Path,Target : String) return Boolean is
      Depth : Natural:=0; Start : Positive:=Target'First;
   begin
      if Target'Length=0 or else Target(Target'First)='/' then return False; end if;
      for C of Path loop if C='/' then Depth:=Depth+1; end if; end loop;
      for J in Target'First..Target'Last+1 loop
         if J=Target'Last+1 or else Target(J)='/' then
            if J=Start then return False; end if;
            if Target(Start..J-1)=".." then
               if Depth=0 then return False; end if; Depth:=Depth-1;
            elsif Target(Start..J-1)="." then null;
            elsif Target(Start..J-1)=".mission" or else Target(Start..J-1)=".mc" then return False;
            else Depth:=Depth+1; end if;
            Start:=J+1;
         end if;
      end loop;
      return True;
   end Safe_Link;
   procedure Materialize(C : in out Context; I : Positive; Desired, Expected : Shape; Status : out Outcome) is
      Path : constant String:=MC_Text.Image(C.Plan.Changes(I).Path);
      Slash : Natural:=0; Current, Temp_Shape : Shape;
      Source, Target : MC_FS.File; V : MC_FS.Entry_Info;
      B : Bytes(1..MC_FS.Max_Xattr_Bytes); Used : Natural; Offset : Counter:=0;
   begin
      Capture(C,Path,False,Current,Status); if Status/=OK then return; end if;
      if Current=Desired then Status:=OK; return; end if;
      if Current/=Expected then Status:=Conflict; return; end if;
      Guard(C,"file-effect",Status); if Status/=OK then return; end if;
      if Desired.Node_Kind=Absent then
         MC_FS.Remove(C.Root,Path,Expected.Node_Kind=Directory,Status); return;
      end if;
      for J in Path'Range loop if Path(J)='/' then Slash:=J; end if; end loop;
      declare Temp : constant String:= (if Slash=0 then "" else Path(Path'First..Slash)) &
        ".mc-tmp-" & MC_Hex.Encode(C.Plan.Transaction_ID) & "-" & Image_Of(I);
      begin
         MC_FS.Stat(C.Root,Temp,V,Status); if Status/=OK then return; end if;
         if V.Kind/=MC_FS.Absent then
            -- This reserved name is owned by the logged intent. Never recurse.
            -- A nonempty temp directory or unrecognized type is an inspection task.
            if V.Kind not in MC_FS.Regular | MC_FS.Directory | MC_FS.Symbolic_Link
              or else (V.UID/=Word(MC_Posix.Euid) and then V.UID/=Desired.UID)
            then Status:=Conflict; return; end if;
            MC_FS.Remove(C.Root,Temp,V.Kind=MC_FS.Directory,Status); if Status/=OK then return; end if;
         end if;
         case Desired.Node_Kind is
            when Regular =>
               MC_Store.Open_Object(C.Store,Desired.Content,Source,Status); if Status/=OK then return; end if;
               MC_FS.Create_New(C.Root,Temp,Target,Status);
               if Status/=OK then MC_FS.Close(Source); return; end if;
               loop
                  MC_FS.Read_At(Source,Offset,B,Used,Status); exit when Status/=OK or else Used=0;
                  MC_FS.Write_All(Target,B(1..Used),Status); exit when Status/=OK;
                  Offset:=Offset+Counter(Used);
               end loop;
               MC_FS.Close(Source);
            when Directory =>
               MC_FS.Make_Directory(C.Root,Temp,Status);
               if Status=OK then MC_FS.Open_Read(C.Root,Temp,Target,Status); end if;
            when Symbolic_Link =>
               MC_Store.Read_Object(C.Store,Desired.Content,B,Used,Status); if Status/=OK then return; end if;
               declare Link : String(1..Used); begin
                  for J in Link'Range loop Link(J):=Character'Val(B(J)); end loop;
                  if not Safe_Link(Path,Link) then Status:=Denied; return; end if;
                  MC_FS.Make_Link(C.Root,Temp,Link,Status);
               end;
            when Absent => Status:=Invalid_Input;
         end case;
         if Status/=OK then MC_FS.Close(Target); return; end if;
         MC_Store.Read_Object(C.Store,Desired.Xattrs,B,Used,Status);
         if Status/=OK then MC_FS.Close(Target); return; end if;
         if Desired.Node_Kind=Symbolic_Link then
            MC_FS.Set_Link_Owner(C.Root,Temp,Desired.UID,Desired.GID,Status);
            if Status=OK then MC_FS.Set_Link_Xattrs(C.Root,Temp,B(1..Used),Status); end if;
         else
            V.Kind:=(if Desired.Node_Kind=Regular then MC_FS.Regular else MC_FS.Directory);
            V.Mode:=Desired.Mode; V.UID:=Desired.UID; V.GID:=Desired.GID;
            V.Mtime_Sec:=Desired.Mtime_Sec; V.Mtime_Nsec:=Desired.Mtime_Nsec;
            MC_FS.Set_Metadata(Target,V,Status);
            if Status=OK then MC_FS.Set_Xattrs(Target,B(1..Used),Status); end if;
            MC_FS.Close(Target);
         end if;
         if Status/=OK then return; end if;
         Capture(C,Temp,False,Temp_Shape,Status); if Status/=OK then return; end if;
         if Temp_Shape/=Desired then Status:=Corrupt; return; end if;
         Guard(C,"publish-file",Status); if Status/=OK then return; end if;
         Capture(C,Path,False,Current,Status); if Status/=OK then return; end if;
         if Current/=Expected then Status:=Conflict; return; end if;
         MC_FS.Rename(C.Root,Temp,Path,Expected.Node_Kind=Absent,Status);
      end;
   exception when others => MC_FS.Close(Source); MC_FS.Close(Target); Status:=Indeterminate;
   end Materialize;
   procedure Apply(C : in out Context; Status : out Outcome) is
      View : Actual_Image; Seen : Shape; V : Log_View;
   begin
      Guard(C,"apply",Status); if Status/=OK then return; end if;
      if MC_Log.Has_Torn_Tail(C.Journal) then Status:=Indeterminate; return; end if;
      Read_Log(C,V,Status); if Status/=OK then return; end if;
      if C.Root_State.Generation/=C.Plan.Base_Generation or else V.Phase not in Forward | Ready_To_Commit
      then Status:=Conflict; return; end if;
      Inspect(C,View,Status); if Status/=OK then return; end if;
      if V.Phase=Ready_To_Commit then
         Status:=(if View=All_After then OK else Conflict); return;
      end if;
      for I in V.Next_Index..C.Plan.Count loop
         Guard(C,"apply",Status); if Status/=OK then return; end if;
         Emit(C,Apply_Intent,I,C.Plan_Digest,Status); if Status/=OK then return; end if;
         Materialize(C,I,C.Plan.Changes(I).After,C.Plan.Changes(I).Before,Status);
         if Status/=OK then C.Poisoned:=True; return; end if;
         Capture(C,MC_Text.Image(C.Plan.Changes(I).Path),False,Seen,Status);
         if Status/=OK or else Seen/=C.Plan.Changes(I).After then C.Poisoned:=True; Status:=Conflict; return; end if;
         Emit(C,Apply_Done,I,C.Plan_Digest,Status); if Status/=OK then return; end if;
      end loop;
      -- A durable "done" record must still agree with the current image.
      -- This is not merely an all-before/all-after membership check.
      Inspect(C,View,Status); if Status/=OK then return; end if;
      if View/=All_After then Status:=Conflict; return; end if;
      Emit(C,Applied,0,C.Plan_Digest,Status);
   exception when others => C.Poisoned:=True; Status:=Indeterminate;
   end Apply;
   procedure Commit(C : in out Context; Health_Receipt : Digest; Status : out Outcome) is
      View : Actual_Image; Receipt : MC_FS.File; V : Log_View;
   begin
      Guard(C,"commit",Status,Health_Receipt); if Status/=OK then return; end if;
      if MC_Log.Has_Torn_Tail(C.Journal) then Status:=Indeterminate; return; end if;
      Read_Log(C,V,Status); if Status/=OK then return; end if;
      if C.Root_State.Generation/=C.Plan.Base_Generation
        or else V.Phase not in Ready_To_Commit | Commit_Pending then Status:=Conflict; return; end if;
      if V.Phase=Commit_Pending and then Health_Receipt/=V.Receipt then
         Status:=Conflict; return;
      end if;
      -- Reauthorization may be fresh, but the logged decision receipt is immutable.
      -- The receipt must be authenticated, plan-bound and fresh in Authorize.
      MC_Store.Open_Object(C.Store,Health_Receipt,Receipt,Status); MC_FS.Close(Receipt);
      if Status/=OK then return; end if;
      Inspect(C,View,Status); if Status/=OK then return; end if;
      if View/=All_After then Status:=Conflict; return; end if;
      Emit(C,Commit_Intent,0,Health_Receipt,Status); if Status/=OK then return; end if;
      C.Root_State.Generation:=C.Plan.Target_Generation; C.Root_State.Accepted_Plan:=C.Plan_Digest;
      C.Root_State.Package_Set:=C.Plan.Package_Set;
      -- Keep Active_Transaction through durable Committed, then clear it. Resume
      -- reconciles the commit-intent/root.state publication window explicitly.
      Persist_State(C,Status); if Status/=OK then return; end if;
      Emit(C,Committed,0,Health_Receipt,Status); if Status/=OK then return; end if;
      C.Root_State.Active_Transaction:=Zero_Identity; C.Root_State.Active_Plan:=Zero_Digest;
      Persist_State(C,Status);
   exception when others => C.Poisoned:=True; Status:=Indeterminate;
   end Commit;
   procedure Restore(C : in out Context; Compatibility_Receipt : Digest; Status : out Outcome) is
      View : Actual_Image; Receipt : MC_FS.File; Seen : Shape; V : Log_View; Start : Natural;
   begin
      Guard(C,"restore",Status,Compatibility_Receipt); if Status/=OK then return; end if;
      if C.Root_State.Generation/=C.Plan.Base_Generation then Status:=Denied; return; end if;
      if MC_Log.Has_Torn_Tail(C.Journal) then Status:=Indeterminate; return; end if;
      Read_Log(C,V,Status); if Status/=OK then return; end if;
      if V.Phase not in Forward | Ready_To_Commit | Reverse_Change then Status:=Conflict; return; end if;
      if V.Phase=Reverse_Change and then Compatibility_Receipt/=V.Receipt then
         Status:=Conflict; return;
      end if;
      Start:=(if V.Phase=Reverse_Change then V.Next_Index else C.Plan.Count);
      MC_Store.Open_Object(C.Store,Compatibility_Receipt,Receipt,Status); MC_FS.Close(Receipt);
      if Status/=OK then return; end if;
      Inspect(C,View,Status); if Status/=OK then return; end if;
      for I in reverse 1..Start loop
         Guard(C,"restore",Status,Compatibility_Receipt); if Status/=OK then return; end if;
         Check_Objects(C,C.Plan.Changes(I).Before,Status); if Status/=OK then return; end if;
         Emit(C,Restore_Intent,I,Compatibility_Receipt,Status); if Status/=OK then return; end if;
         Materialize(C,I,C.Plan.Changes(I).Before,C.Plan.Changes(I).After,Status);
         if Status/=OK then C.Poisoned:=True; return; end if;
         Capture(C,MC_Text.Image(C.Plan.Changes(I).Path),False,Seen,Status);
         if Status/=OK or else Seen/=C.Plan.Changes(I).Before then C.Poisoned:=True; Status:=Conflict; return; end if;
         Emit(C,Restore_Done,I,Compatibility_Receipt,Status); if Status/=OK then return; end if;
      end loop;
      -- Recheck the complete restored image, not only each last-written path.
      Inspect(C,View,Status); if Status/=OK then return; end if;
      if View/=All_Before then Status:=Conflict; return; end if;
      Emit(C,Restored,0,Compatibility_Receipt,Status); if Status/=OK then return; end if;
      C.Root_State.Active_Transaction:=Zero_Identity; C.Root_State.Active_Plan:=Zero_Digest;
      Persist_State(C,Status);
   exception when others => C.Poisoned:=True; Status:=Indeterminate;
   end Restore;
   procedure Reconcile_Terminal(C : in out Context; Status : out Outcome) is
      V : Log_View; Image : Actual_Image;
   begin
      Guard(C,"finish-terminal",Status); if Status/=OK then return; end if;
      if MC_Log.Has_Torn_Tail(C.Journal) then Status:=Indeterminate; return; end if;
      Read_Log(C,V,Status); if Status/=OK then return; end if;
      Inspect(C,Image,Status); if Status/=OK then return; end if;
      if C.Root_State.Generation=C.Plan.Target_Generation then
         if C.Root_State.Accepted_Plan/=C.Plan_Digest or else C.Root_State.Package_Set/=C.Plan.Package_Set
           or else Image/=All_After or else V.Phase not in Commit_Pending | Forward_Final
         then Status:=Conflict; return; end if;
         -- A new request may authorize reconciliation, but cannot replace the
         -- durable decision receipt with a different health assertion.
         Guard(C,"finish-terminal",Status,V.Receipt); if Status/=OK then return; end if;
         if V.Phase=Commit_Pending then
            -- No re-activation and no new generation decision: publication already
            -- happened. Reconcile its immutable receipt rather than repeat commit.
            Emit(C,Committed,0,V.Receipt,Status); if Status/=OK then return; end if;
         end if;
      elsif C.Root_State.Generation=C.Plan.Base_Generation and then V.Phase=Reverse_Final
        and then Image=All_Before then
         Guard(C,"finish-terminal",Status,V.Receipt); if Status/=OK then return; end if;
      else Status:=Conflict; return;
      end if;
      C.Root_State.Active_Transaction:=Zero_Identity; C.Root_State.Active_Plan:=Zero_Digest;
      Persist_State(C,Status);
   exception when others => C.Poisoned:=True; Status:=Indeterminate;
   end Reconcile_Terminal;
   procedure Repair_Torn_Journal(C : in out Context; Status : out Outcome) is
      B : Bytes(1..256); Used : Natural; D : Digest;
      Audit : MC_Log.Journal; E : MC_Log_Format.Log_Entry;
   begin
      Guard(C,"repair-journal",Status); if Status/=OK then return; end if;
      MC_Log.Export_Tail(C.Journal,B,Used,Status); if Status/=OK then return; end if;
      MC_Store.Put(C.Store,B(1..Used),D,Status); if Status/=OK then return; end if;
      MC_Log.Open(C.State_Directory,"repairs.log",C.Root_State.Root_ID,Audit,Status);
      if Status/=OK then MC_Log.Close(Audit); return; end if;
      E.Kind:=400; E.Root_ID:=C.Root_State.Root_ID; E.Operation_ID:=C.Plan.Transaction_ID;
      E.Epoch:=C.Plan.Epoch; E.Token:=C.Plan.Fence; E.Index:=MC_Log.Length(C.Journal);
      E.Generation:=C.Root_State.Generation; E.Object:=D;
      MC_Log.Append(Audit,E,Status);
      if Status=OK then MC_Log.Repair_Tail(C.Journal,D,Status); end if;
      if Status=OK then E.Kind:=401; MC_Log.Append(Audit,E,Status); end if;
      MC_Log.Close(Audit);
      -- Never append a repair marker AFTER a terminal transaction record. Repairs
      -- have a separate audit stream; the transaction's effect history is preserved.
   exception when others => MC_Log.Close(Audit); Status:=Indeterminate;
   end Repair_Torn_Journal;
   function Generation(C : Context) return Counter is (C.Root_State.Generation);
   function Accepted_Plan(C : Context) return Digest is (C.Root_State.Accepted_Plan);
   function Has_Active_Change(C : Context) return Boolean is (C.Root_State.Active_Transaction/=Zero_Identity);
   procedure Close(C : in out Context) is
   begin
      MC_Log.Close(C.Journal); MC_Store.Close(C.Store); MC_FS.Close(C.Root_Lock);
      MC_FS.Close(C.State_Directory); MC_FS.Close(C.Root);
      if C.Plan/=null then Free(C.Plan); end if;
      C.Opened:=False; C.Poisoned:=False;
   end Close;
end Pkg_File_Engine;
