-- SPDX-License-Identifier: MIT
with MC_FS; with MC_Atomic; with MC_Witness; with MC_Numbers;
package body MC_Request_Files with SPARK_Mode => Off is
   use type MC_FS.Entry_Kind;
   procedure Load(Directory : String; Header : out MC_Protocol.Frame_Header;
      Body_Data : out MC_Requests.Request_Bytes; Signature : out MC_Signatures.Signature;
      Witnesses : out MC_Gate.Witness_Set; Status : out Outcome) is
      R : MC_FS.Root; B : Envelope; W : Bytes(1..288); Used : Natural; Info : MC_FS.Entry_Info;
   begin
      Header:=(others=>0); Body_Data:=(others=>0); Signature:=(others=>0); Witnesses:=(others=><>);
      MC_FS.Open_Root(Directory,R,Status,Private_Only=>True); if Status/=OK then return; end if;
      MC_Atomic.Read(R,"envelope.bin",B,Used,Status);
      if Status=OK and then Used/=Envelope_Size then Status:=Invalid_Input; end if;
      if Status/=OK then MC_FS.Close(R); return; end if;
      Header:=B(1..160); Body_Data:=B(161..352); Signature:=B(353..416);
      for F in MC_Witness.Fact loop
         declare Name : constant String:="witness-" & MC_Numbers.Image(Counter(MC_Witness.Fact'Pos(F))) & ".bin"; begin
            MC_FS.Stat(R,Name,Info,Status); exit when Status/=OK;
            if Info.Kind/=MC_FS.Absent then
               MC_Atomic.Read(R,Name,W,Used,Status); exit when Status/=OK;
               if Used/=288 then Status:=Invalid_Input; exit; end if;
               Witnesses.Present(F):=True; Witnesses.Statements(F):=W(1..224); Witnesses.Signatures(F):=W(225..288);
            end if;
         end;
      end loop;
      MC_FS.Close(R);
   exception when others=>MC_FS.Close(R); Status:=IO_Error;
   end;
end MC_Request_Files;
