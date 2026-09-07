-- SPDX-License-Identifier: MIT
with MC_FS; with MC_Atomic; with MC_Clock; with MC_Text;
with Pkg_Image_Inspector; with Pkg_File_Plan; with Pkg_Root_State;
package body Pkg_Scrubber with SPARK_Mode=>Off is
   procedure Scan(Root_Path,State_Path : String; Baseline : Pkg_Inventory.Manifest;
      Maximum_Read_Bytes, Deadline_Boottime_Ms : Counter;
      Findings : out Pkg_Self_Repair.Finding_Array;
      Matched,Different,Unknown : out Natural; Status : out Outcome) is
      R,State_Dir : MC_FS.Root; Lock : MC_FS.File; B,Final_State : Pkg_Root_State.Frame;
      Current : Pkg_Root_State.State; Marker : Identity; Used : Natural;
      Now,Read_Total,Read_One : Counter:=0; Item_Status : Outcome;
      procedure Finish is begin MC_FS.Close(Lock); MC_FS.Close(R); MC_FS.Close(State_Dir); end;
   begin
      Findings:=(others=><>); Matched:=0; Different:=0; Unknown:=0; Status:=Denied;
      if Root_Path="/" or else not Pkg_Inventory.Valid(Baseline) or else Maximum_Read_Bytes=0 then return; end if;
      MC_FS.Open_Root(State_Path,State_Dir,Status,Private_Only=>True); if Status/=OK then return; end if;
      MC_FS.Open_Locked(State_Dir,"root.lock",Lock,Status,Create_If_Missing=>False); if Status/=OK then Finish; return; end if;
      MC_FS.Open_Root(Root_Path,R,Status); if Status/=OK then Finish; return; end if;
      MC_Atomic.Read(R,".mission/root.id",Marker,Used,Status);
      if Status/=OK or else Used/=Marker'Length or else Marker/=Baseline.Root_ID then Status:=Denied; Finish; return; end if;
      MC_Atomic.Read(State_Dir,"root.state",B,Used,Status);
      if Status/=OK or else Used/=B'Length then Status:=Corrupt; Finish; return; end if;
      Pkg_Root_State.Decode(B,Current,Status);
      if Status/=OK or else Current.Root_ID/=Baseline.Root_ID or else Current.Generation/=Baseline.Generation
        or else Current.Package_Set/=Baseline.Package_Set or else Current.Active_Transaction/=Zero_Identity
      then Status:=Conflict; Finish; return; end if;
      for I in 1..Baseline.Count loop
         MC_Clock.Boottime_Milliseconds(Now,Status);
         if Status/=OK or else Now>=Deadline_Boottime_Ms then Status:=Stale; Finish; return; end if;
         if Read_Total>=Maximum_Read_Bytes then Status:=Exhausted; Finish; return; end if;
         Pkg_Image_Inspector.Inspect(R,MC_Text.Image(Baseline.Items(I).Path),Maximum_Read_Bytes-Read_Total,
            Findings(I).Actual,Read_One,Item_Status);
         if Read_One>Maximum_Read_Bytes-Read_Total then Status:=Exhausted; Finish; return; end if;
         Read_Total:=Read_Total+Read_One;
         if Item_Status=OK then
            Findings(I).Known:=True;
            if Pkg_File_Plan.Equal(Findings(I).Actual,Baseline.Items(I).Desired) then Matched:=Matched+1;
            else Different:=Different+1; end if;
         else Unknown:=Unknown+1; end if;
      end loop;
      MC_Atomic.Read(State_Dir,"root.state",Final_State,Used,Status);
      if Status/=OK or else Used/=B'Length or else B/=Final_State then Status:=Conflict; Finish; return; end if;
      MC_Clock.Boottime_Milliseconds(Now,Status);
      if Status=OK and then Now>=Deadline_Boottime_Ms then Status:=Stale; end if;
      Finish;
   exception when others=>Finish; Status:=IO_Error;
   end Scan;
end Pkg_Scrubber;
