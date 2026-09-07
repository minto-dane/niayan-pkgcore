-- SPDX-License-Identifier: MIT
with MC_Posix; with MC_FS; with MC_Clock; with Interfaces.C; with System;
package body MC_Command with SPARK_Mode => Off is
   use Interfaces.C; use MC_Posix;
   use type Word; use type MC_FS.Entry_Kind; use type MC_FS.Entry_Info;
   type Pair is array(0..1) of aliased int with Convention=>C;
   function Pipe2(P : System.Address; Flags : int) return int
     with Import,Convention=>C,External_Name=>"pipe2";
   function Fork return int with Import,Convention=>C,External_Name=>"fork";
   function Getpid return int with Import,Convention=>C,External_Name=>"getpid";
   function Getppid return int with Import,Convention=>C,External_Name=>"getppid";
   function Dup2(A,B : int) return int with Import,Convention=>C,External_Name=>"dup2";
   function Setsid return int with Import,Convention=>C,External_Name=>"setsid";
   function Prctl(Option : int; A,B,C,D : unsigned_long) return int
     with Import,Convention=>C,External_Name=>"prctl";
   function Close_Range(First,Last,Flags : unsigned) return int
     with Import,Convention=>C,External_Name=>"close_range";
   function Execveat(D : int; Path,Argv,Envp : System.Address; Flags : int) return int
     with Import,Convention=>C,External_Name=>"execveat";
   procedure Exit_Immediately(Code : int) with Import,Convention=>C,External_Name=>"_exit",No_Return;
   function Kill(PID,Signal : int) return int with Import,Convention=>C,External_Name=>"kill";
   function Pidfd_Open(PID : int; Flags : unsigned) return int
     with Import,Convention=>C,External_Name=>"pidfd_open";
   function Waitpid(PID : int; S : access int; Options : int) return int
     with Import,Convention=>C,External_Name=>"waitpid";
   type Poll_Descriptor is record D : int; Events,Returned : short; end record with Convention=>C;
   type Poll_Array is array(1..3) of aliased Poll_Descriptor with Convention=>C;
   function Poll(F : System.Address; N : unsigned_long; Timeout : int) return int
     with Import,Convention=>C,External_Name=>"poll";
   type C_String is array(size_t range 0..4096) of aliased char with Convention=>C;
   type String_Array is array(Natural range 0..Max_Arguments) of aliased C_String;
   type Pointer_Array is array(Natural range <>) of System.Address with Convention=>C;
   procedure Run(C : Invocation; Input : Bytes; R : out Result; Status : out Outcome) is
      Args : aliased String_Array := (others=>(others=>nul));
      Argv : aliased Pointer_Array(0..Max_Arguments+1):=(others=>System.Null_Address);
      Env1 : aliased char_array:=To_C("LANG=C"); Env2 : aliased char_array:=To_C("LC_ALL=C");
      Env3 : aliased char_array:=To_C("PATH=/usr/sbin:/usr/bin"); Env4 : aliased char_array:=To_C("HOME=/nonexistent");
      Envp : aliased Pointer_Array(0..4):=(Env1'Address,Env2'Address,Env3'Address,Env4'Address,System.Null_Address);
      Empty : aliased char_array:=To_C("");
      RP : MC_FS.Root; Executable : MC_FS.File; D : Digest; L : Counter;
      V,V_After : MC_FS.Entry_Info; Magic : Bytes(1..4); Got : Natural;
      Input_Pipe, Output_Pipe : aliased Pair:=(others=>-1);
      Parent_ID : int:=-1;
      Child : int:=-1; Child_FD : int:=-1;
      Exec_FD, Extra_FD, Child_Input, Child_Output : int:=-1; Exit_State : aliased int:=0;
      P : aliased Poll_Array:=((D=>-1,Events=>1,Returned=>0),
        (D=>-1,Events=>4,Returned=>0),(D=>-1,Events=>1,Returned=>0));
      Ignored, Ready, Waited : int; N : long; Now : Counter;
      Written : Natural:=0; Read_Buffer : Bytes(1..8192);
      Output_Open, Child_Exited, Child_Reaped, Forced : Boolean:=False;
      Cleanup_Complete : Boolean:=True;
      Slash : Natural:=0;
      pragma Unreferenced(Ignored);
      procedure Close_FD(F : in out int) is
      begin if F>=0 then Ignored:=MC_Posix.Close(F); F:=-1; end if; end;
      procedure Cleanup is
      begin
         Close_FD(Input_Pipe(0)); Close_FD(Input_Pipe(1));
         Close_FD(Output_Pipe(0)); Close_FD(Output_Pipe(1));
         Close_FD(Exec_FD); Close_FD(Extra_FD); Close_FD(Child_FD);
         Close_FD(Child_Input); Close_FD(Child_Output);
         MC_FS.Close(Executable); MC_FS.Close(RP);
      end;
      procedure Terminate_Child is
         Stop_Status : Outcome; Stop_Start, Stop_Now : Counter;
         Sleep_Poll : aliased Poll_Array := (others => (D=>-1,Events=>0,Returned=>0));
      begin
         if Child>0 and then not Child_Reaped then
            -- Retain the leader (including its zombie) until group cleanup. A
            -- reaped PID/PGID may be reused; never signal it after waitpid succeeds.
            -- Stop the leader first so it cannot fork while its group is killed.
            Ignored:=Kill(Child,9);
            if Ignored/=0 and then Errno_Location.all/=3 then Cleanup_Complete:=False; end if; -- ESRCH
            Ignored:=Kill(-Child,9);
            if Ignored/=0 and then Errno_Location.all/=3 then Cleanup_Complete:=False; end if;
            MC_Clock.Boottime_Milliseconds(Stop_Start,Stop_Status);
            if Stop_Status/=OK then Cleanup_Complete:=False; return; end if;
            loop
               Waited:=Waitpid(Child,Exit_State'Access,1);
               if Waited=Child then Child_Reaped:=True; return; end if;
               if Waited<0 and then Errno_Location.all/=EINTR then
                  -- ECHILD is not success: another reaper violates Run's exclusive
                  -- child ownership. Do not send another signal to this PID.
                  Child_Reaped:=True; Cleanup_Complete:=False; return;
               end if;
               MC_Clock.Boottime_Milliseconds(Stop_Now,Stop_Status);
               if Stop_Status/=OK or else Stop_Now<Stop_Start
                 or else Stop_Now-Stop_Start>=1_000 then
                  -- Uninterruptible I/O can outlive SIGKILL. Bound this wait and
                  -- return indeterminate; the supervisor owns further containment.
                  Cleanup_Complete:=False; return;
               end if;
               Ignored:=Poll(Sleep_Poll'Address,3,10);
            end loop;
         end if;
      end Terminate_Child;
   begin
      R:=(others=><>); Status:=Invalid_Input;
      if C.Executable_Digest=Zero_Digest or else Input'Length>Max_Message then return; end if;
      declare Path : constant String:=MC_Text.Image(C.Executable); begin
         if Path'Length<2 or else Path(Path'First)/='/' then return; end if;
         for J in Path'Range loop if Path(J)='/' then Slash:=J; end if; end loop;
         if Slash=Path'Last then return; end if;
         MC_FS.Open_Root((if Slash=Path'First then "/" else Path(Path'First..Slash-1)),RP,Status);
         if Status/=OK then return; end if;
         MC_FS.Open_Read(RP,Path(Slash+1..Path'Last),Executable,Status);
         if Status/=OK then Cleanup; return; end if;
      end;
      MC_FS.Info(Executable,V,Status);
      if Status=OK and then (V.Kind/=MC_FS.Regular or else (V.Mode and 8#022#)/=0
        or else (V.Mode and 8#7000#)/=0 or else (V.Mode and 8#111#)=0
        or else (V.UID/=0 and then V.UID/=Word(Euid))) then Status:=Denied; end if;
      if Status=OK then MC_FS.Hash(Executable,512*1024*1024,D,L,Status); end if;
      if Status=OK and then D/=C.Executable_Digest then Status:=Denied; end if;
      if Status=OK then MC_FS.Read_At(Executable,0,Magic,Got,Status); end if;
      if Status=OK and then (Got/=4 or else Magic/=(16#7F#,16#45#,16#4C#,16#46#)) then Status:=Unsupported; end if;
      if Status=OK then MC_FS.Info(Executable,V_After,Status); end if;
      if Status=OK and then V_After/=V then Status:=Stale; end if;
      if Status/=OK then Cleanup; return; end if;
      MC_Clock.Boottime_Milliseconds(Now,Status);
      if Status/=OK or else Now>=C.Deadline or else C.Deadline-Now>3_600_000
      then Status:=Stale; Cleanup; return; end if;
      for I in 0..C.Count loop
         declare S : constant String:= (if I=0 then MC_Text.Image(C.Executable) else MC_Text.Image(C.Arguments(I))); begin
            for J in S'Range loop Args(I)(size_t(J-S'First)):=char(S(J)); end loop;
            Argv(I):=Args(I)'Address;
         end;
      end loop;
      if Pipe2(Input_Pipe'Address,O_CLOEXEC)/=0 or else Pipe2(Output_Pipe'Address,O_CLOEXEC)/=0
      then Status:=IO_Error; Cleanup; return; end if;
      -- Stage all child source descriptors above the fixed destination range.
      -- This remains correct even if the caller entered with stdin/out/err closed.
      Exec_FD:=MC_Posix.Dup(int(MC_FS.Native(Executable)),1030,64);
      Child_Input:=MC_Posix.Dup(Input_Pipe(0),1030,64);
      Child_Output:=MC_Posix.Dup(Output_Pipe(1),1030,64);
      if Exec_FD<0 or else Child_Input<0 or else Child_Output<0 then Status:=IO_Error; Cleanup; return; end if;
      if C.Pass_Descriptor>=0 then
         Extra_FD:=MC_Posix.Dup(C.Pass_Descriptor,1030,64);
         if Extra_FD<0 then Status:=IO_Error; Cleanup; return; end if;
      end if;
      Parent_ID:=Getpid; Child:=Fork;
      if Child<0 then Status:=IO_Error; Cleanup; return; end if;
      if Child=0 then
         -- Child branch: C calls only. Descriptors were allocated before fork.
         -- Kill the command helper when its authorizing parent dies. The
         -- post-prctl parent check closes the fork/death registration race.
         -- A submitted service/etcd operation may still outlive this helper;
         -- callers MUST retain unknown outcome and re-observe the remote effect.
         if Prctl(1,9,0,0,0)/=0 or else Getppid/=Parent_ID
           or else Setsid<0 or else Prctl(38,1,0,0,0)/=0 then Exit_Immediately(126); end if;
         if Dup2(Child_Input,0)<0 or else Dup2(Child_Output,1)<0
            or else Dup2(Child_Output,2)<0 or else Dup2(Exec_FD,3)<0
            then Exit_Immediately(126); end if;
         if Extra_FD>=0 then
            if Dup2(Extra_FD,4)<0 or else Close_Range(5,unsigned'Last,0)/=0 then Exit_Immediately(126); end if;
         elsif Close_Range(4,unsigned'Last,0)/=0 then Exit_Immediately(126); end if;
         Ignored:=Execveat(3,Empty'Address,Argv'Address,Envp'Address,AT_EMPTY_PATH);
         Exit_Immediately(127);
      end if;
      Child_FD:=Pidfd_Open(Child,0);
      if Child_FD<0 then
         Terminate_Child; R.State:=Unknown; Status:=Indeterminate; Cleanup; return;
      end if;
      Close_FD(Input_Pipe(0)); Close_FD(Output_Pipe(1));
      Close_FD(Child_Input); Close_FD(Child_Output);
      -- Both parent pipe ends nonblocking. No blocking write can escape deadline.
      if MC_Posix.Dup(Input_Pipe(1),4,O_NONBLOCK)<0 or else MC_Posix.Dup(Output_Pipe(0),4,O_NONBLOCK)<0
      then Terminate_Child; R.State:=Unknown; Status:=Indeterminate; Cleanup; return; end if;
      Output_Open:=True;
      if Input'Length=0 then Close_FD(Input_Pipe(1)); end if;
      loop
         MC_Clock.Boottime_Milliseconds(Now,Status);
         if Status/=OK or else Now>=C.Deadline then R.State:=Timed_Out; Forced:=True; exit; end if;
         P(1):=(Output_Pipe(0),1,0); P(2):=(Input_Pipe(1),4,0);
         P(3):=((if Child_Exited then -1 else Child_FD),1,0);
         Ready:=Poll(P'Address,3,int(Counter'Min(100,C.Deadline-Now)));
         if Ready<0 and then Errno_Location.all/=EINTR then R.State:=Unknown; Forced:=True; exit; end if;
         if Output_Open then
            loop
               N:=MC_Posix.Read(Output_Pipe(0),Read_Buffer'Address,Read_Buffer'Length);
               if N>0 then
                  if Natural(N)>Max_Output-R.Used then R.State:=Output_Limit; Forced:=True; exit; end if;
                  R.Output(R.Used+1..R.Used+Natural(N)):=Read_Buffer(1..Natural(N)); R.Used:=R.Used+Natural(N);
               elsif N=0 then Close_FD(Output_Pipe(0)); Output_Open:=False; exit;
               elsif Errno_Location.all=EAGAIN then exit;
               elsif Errno_Location.all=EINTR then null;
               else R.State:=Unknown; Forced:=True; exit; end if;
            end loop;
         end if;
         exit when Forced;
         if Input_Pipe(1)>=0 then
            -- Ignore SIGPIPE must be installed once by the executable before Run;
            -- see MC_Runtime.Initialize. A closed peer is an observed failed input.
            N:=MC_Posix.Write(Input_Pipe(1),Input(Input'First+Written)'Address,size_t(Input'Length-Written));
            if N>0 then Written:=Written+Natural(N);
            elsif N<0 and then Errno_Location.all in EINTR | EAGAIN then null;
            else Close_FD(Input_Pipe(1)); end if;
            if Written=Input'Length then Close_FD(Input_Pipe(1)); end if;
         end if;
         if P(3).Returned/=0 then
            if (P(3).Returned mod 2)=1 then Child_Exited:=True;
            else R.State:=Unknown; Forced:=True; exit; end if;
         end if;
         exit when Child_Exited and then not Output_Open;
      end loop;
      -- Cleanup also runs after a normally exited leader. Its descendants must
      -- not survive just because they retain stdout or close it before escaping.
      -- This is process-group cleanup, NOT a cgroup/fencing/quiescence proof.
      Terminate_Child;
      if not Cleanup_Complete then R.State:=Unknown;
      elsif not Forced then
         if (Exit_State mod 128)/=0 then R.State:=Signalled;
         else R.State:=Exited; R.Exit_Code:=Natural((Exit_State/256) mod 256); end if;
      end if;
      if R.State=Exited and then Written=Input'Length then
         Status:=(if R.Exit_Code=0 then OK elsif C.May_Have_External_Effects then Indeterminate else IO_Error);
      else Status:=(if C.May_Have_External_Effects then Indeterminate else IO_Error); end if;
      Cleanup;
   exception when others => Terminate_Child; Cleanup; R.State:=Unknown; Status:=Indeterminate;
   end Run;
end MC_Command;
