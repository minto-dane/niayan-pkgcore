-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body MC_Health_Report with SPARK_Mode is
   use type Byte; use type Wide;
   function Valid(R : Report) return Boolean is
     (R.Cluster_ID/=Zero_Identity and then R.Node_ID/=Zero_Identity and then R.Resource_ID/=Zero_Identity
      and then R.Configuration/=Zero_Digest and then R.Recovery_Policy/=Zero_Digest
      and then R.Stamp.Boot_ID/=Zero_Identity and then R.Stamp.Sequence>0
      and then R.Stamp.Expires_At>R.Stamp.Observed_At
      and then (not R.Business_Healthy or else (R.Result=Healthy and then R.Invocation_ID/=Zero_Identity)));
   function Encode(R : Report) return Frame is
      B : Frame:=(others=>0); M : constant String:="MCHLTH01";
      function Bit(V : Boolean) return Byte is (if V then 1 else 0);
   begin
      for I in M'Range loop B(I):=Byte(Character'Pos(M(I))); end loop;
      B(9..24):=R.Cluster_ID; B(25..40):=R.Node_ID; B(41..56):=R.Resource_ID; B(57..72):=R.Invocation_ID;
      B(73..104):=R.Configuration; B(105..136):=R.Recovery_Policy; B(137..152):=R.Stamp.Boot_ID;
      MC_Codec.Put64(B,153,Wide(R.Stamp.Sequence)); MC_Codec.Put64(B,161,Wide(R.Stamp.Observed_At));
      MC_Codec.Put64(B,169,Wide(R.Stamp.Expires_At)); B(177):=Byte(Condition'Pos(R.Result));
      B(178):=Bit(R.Config_Valid); B(179):=Bit(R.Dependencies_Ready); B(180):=Bit(R.Data_Compatible);
      B(181):=Bit(R.Ownership_Exclusive); B(182):=Bit(R.Business_Healthy);
      B(183):=Bit(R.Maintenance); B(184):=Bit(R.Emergency_Stop);
      B(225..256):=MC_SHA256.Hash(B(1..224)); return B;
   end;
   procedure Decode(B : Bytes; R : out Report; Status : out Outcome) is
      F : Frame; M : constant String:="MCHLTH01";
   begin
      R:=(others=><>); Status:=Invalid_Input; if B'Length/=F'Length then return; end if; F:=B;
      for I in M'Range loop if F(I)/=Byte(Character'Pos(M(I))) then return; end if; end loop;
      if F(225..256)/=MC_SHA256.Hash(F(1..224)) then Status:=Corrupt; return; end if;
      if F(177)>Byte(Condition'Pos(Condition'Last)) then return; end if;
      for I in 178..184 loop if F(I)>1 then return; end if; end loop;
      for I in 0..2 loop if MC_Codec.U64(F,153+I*8)>Wide(Counter'Last) then return; end if; end loop;
      R.Cluster_ID:=F(9..24); R.Node_ID:=F(25..40); R.Resource_ID:=F(41..56); R.Invocation_ID:=F(57..72);
      R.Configuration:=F(73..104); R.Recovery_Policy:=F(105..136); R.Stamp.Boot_ID:=F(137..152);
      R.Stamp.Sequence:=Counter(MC_Codec.U64(F,153)); R.Stamp.Observed_At:=Counter(MC_Codec.U64(F,161));
      R.Stamp.Expires_At:=Counter(MC_Codec.U64(F,169)); R.Result:=Condition'Val(F(177));
      R.Config_Valid:=F(178)=1; R.Dependencies_Ready:=F(179)=1; R.Data_Compatible:=F(180)=1;
      R.Ownership_Exclusive:=F(181)=1; R.Business_Healthy:=F(182)=1; R.Maintenance:=F(183)=1; R.Emergency_Stop:=F(184)=1;
      if not Valid(R) or else Encode(R)/=F then return; end if;
      Status:=OK;
   end;
end MC_Health_Report;
