-- SPDX-License-Identifier: MIT
with MC_FS; with MC_Atomic; with MC_Hex; with MC_Paths;
package body MC_Tools with SPARK_Mode => Off is
   use type MC_FS.Entry_Kind;
   procedure Set_Argument(C : in out MC_Command.Invocation; Text : String; Status : out Outcome) is
   begin
      Status:=Exhausted; if C.Count=MC_Command.Max_Arguments then return; end if;
      MC_Text.Set(C.Arguments(C.Count+1),Text,Status);
      if Status=OK then C.Count:=C.Count+1; end if;
   end;
   procedure Invoke(T : Tool; Arguments : MC_Command.Argument_Array; Count : Natural;
      Deadline : Counter; Mutation : Boolean; Result : out MC_Command.Result; Status : out Outcome) is
      C : MC_Command.Invocation;
   begin
      Status:=Invalid_Input; Result:=(others=><>);
      if Count>MC_Command.Max_Arguments then return; end if;
      C.Executable:=T.Path; C.Executable_Digest:=T.Content;
      C.Arguments:=Arguments; C.Count:=Count; C.Deadline:=Deadline;
      C.May_Have_External_Effects:=Mutation; MC_Command.Run(C,Bytes'(1..0=>0),Result,Status);
   end;
   procedure Load(Directory, Name : String; T : out Tool; Status : out Outcome) is
      R : MC_FS.Root; F : MC_FS.File; Info : MC_FS.Entry_Info;
      B : Bytes(1..4_164); Used : Natural; LF : Natural:=0;
   begin
      T:=(others=><>); Status:=Invalid_Input;
      if not MC_Text.Identifier(Name) then return; end if;
      MC_FS.Open_Root(Directory,R,Status,Private_Only=>True); if Status/=OK then return; end if;
      MC_FS.Open_Read(R,Name & ".tool",F,Status);
      if Status=OK then MC_FS.Info(F,Info,Status); end if;
      MC_FS.Close(F);
      if Status=OK and then Info.Mode not in 8#400# | 8#600# then Status:=Denied; end if;
      if Status=OK then MC_Atomic.Read(R,Name & ".tool",B,Used,Status); end if;
      MC_FS.Close(R); if Status/=OK then return; end if;
      for I in 1..Used loop if B(I)=10 then LF:=I; exit; end if; end loop;
      if LF<3 or else Used/=LF+65 or else B(Used)/=10 then Status:=Invalid_Input; return; end if;
      declare P : String(1..LF-1); H : String(1..64); begin
         for I in P'Range loop P(I):=Character'Val(B(I)); end loop;
         for I in H'Range loop H(I):=Character'Val(B(LF+I)); end loop;
         if P(1)/='/' or else not MC_Paths.Safe_Relative(P(2..P'Last)) then Status:=Denied; return; end if;
         MC_Text.Set(T.Path,P,Status); if Status=OK then MC_Hex.Decode(H,T.Content,Status); end if;
         if Status=OK and then T.Content=Zero_Digest then Status:=Denied; end if;
      end;
   exception when others => MC_FS.Close(F); MC_FS.Close(R); Status:=IO_Error;
   end Load;
end MC_Tools;
