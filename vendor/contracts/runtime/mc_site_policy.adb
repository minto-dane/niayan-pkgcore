-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256; with MC_Atomic; with MC_Posix; with MC_Protocol;
package body MC_Site_Policy with SPARK_Mode => Off is
   use type Wide; use type Word; use type MC_FS.Entry_Kind;
   Magic : constant Bytes:=(16#4D#,16#43#,16#50#,16#4F#,16#4C#,16#30#,16#30#,16#32#);
   function Encode(P : Policy) return Frame is
      B : Frame:=(others=>0); Bits : Word:=0; Offset : Natural:=224;
   begin
      B(1..8):=Magic; B(9..24):=P.Root_ID; B(25..40):=P.Scope.Cluster_ID; B(41..56):=P.Scope.Node_ID;
      B(57..72):=P.Scope.Resource_ID; MC_Codec.Put64(B,73,Wide(P.Scope.Membership_Epoch));
      MC_Codec.Put64(B,81,Wide(P.Scope.Fence_Token));
      for K in MC_Protocol.Message_Kind loop if P.Scope.Allowed(K) then Bits:=Bits or 2**MC_Protocol.Message_Kind'Pos(K); end if; end loop;
      MC_Codec.Put32(B,89,Bits); B(97..128):=P.Request_Key; B(129..160):=P.Contract;
      MC_Codec.Put64(B,193,Wide(P.Scope.Maximum_Local_Lease)); MC_Codec.Put64(B,201,Wide(P.Valid_Until));
      MC_Codec.Put64(B,209,Wide(P.Serial)); MC_Codec.Put64(B,217,Wide(P.Maximum_Witness_Age));
      for K in MC_Witness.Fact loop B(Offset+1..Offset+32):=P.Observers(K); Offset:=Offset+32; end loop;
      B(481..512):=MC_SHA256.Hash(B(1..480)); return B;
   end;
   procedure Decode(B : Bytes; P : out Policy; Status : out Outcome) is
      Bits : Word; Offset : Natural:=224;
      type Offsets is array(1..6) of Positive; O : constant Offsets:=(73,81,193,201,209,217);
   begin
      P:=(others=><>); Status:=Invalid_Input;
      if B'First/=1 or else B'Length/=512 or else B(1..8)/=Magic or else B(481..512)/=MC_SHA256.Hash(B(1..480)) then return; end if;
      for J in 93..96 loop if B(J)/=0 then return; end if; end loop;
      for J in 161..192 loop if B(J)/=0 then return; end if; end loop;
      for J in 385..480 loop if B(J)/=0 then return; end if; end loop;
      for J of O loop if MC_Codec.U64(B,J)>Wide(Counter'Last) then return; end if; end loop;
      Bits:=MC_Codec.U32(B,89); if Bits>=2**(MC_Protocol.Message_Kind'Pos(MC_Protocol.Message_Kind'Last)+1) then return; end if;
      P.Root_ID:=B(9..24); P.Scope.Cluster_ID:=B(25..40); P.Scope.Node_ID:=B(41..56); P.Scope.Resource_ID:=B(57..72);
      P.Scope.Membership_Epoch:=Counter(MC_Codec.U64(B,73)); P.Scope.Fence_Token:=Counter(MC_Codec.U64(B,81));
      for K in MC_Protocol.Message_Kind loop P.Scope.Allowed(K):=(Bits and 2**MC_Protocol.Message_Kind'Pos(K))/=0; end loop;
      P.Request_Key:=B(97..128); P.Contract:=B(129..160);
      P.Scope.Maximum_Local_Lease:=Counter(MC_Codec.U64(B,193)); P.Valid_Until:=Counter(MC_Codec.U64(B,201));
      P.Serial:=Counter(MC_Codec.U64(B,209)); P.Maximum_Witness_Age:=Counter(MC_Codec.U64(B,217));
      for K in MC_Witness.Fact loop P.Observers(K):=B(Offset+1..Offset+32); Offset:=Offset+32; end loop;
      if P.Root_ID=Zero_Identity or else P.Scope.Resource_ID/=P.Root_ID or else P.Scope.Cluster_ID=Zero_Identity
        or else P.Scope.Node_ID=Zero_Identity or else P.Scope.Membership_Epoch=0 or else P.Scope.Fence_Token=0
        or else P.Scope.Maximum_Local_Lease not in 1..3_600_000 or else P.Maximum_Witness_Age not in 1..60_000
        or else Is_Zero(P.Request_Key) or else P.Contract=Zero_Digest or else P.Serial=0 or else P.Valid_Until=0
      then return; end if;
      for K in MC_Witness.Fact loop
         if Is_Zero(P.Observers(K)) or else P.Observers(K)=P.Request_Key then return; end if;
      end loop;
      Status:=OK;
   end;
   procedure Load(Directory : MC_FS.Root; P : out Policy; Fingerprint : out Digest; Status : out Outcome) is
      B : Frame; Used : Natural; V : MC_FS.Entry_Info;
   begin
      P:=(others=><>); Fingerprint:=Zero_Digest;
      MC_FS.Stat(Directory,"policy.bin",V,Status); if Status/=OK then return; end if;
      if V.Kind/=MC_FS.Regular or else V.Links/=1 or else V.UID/=Word(MC_Posix.Euid)
        or else V.Mode not in 8#400# | 8#600# then Status:=Denied; return; end if;
      MC_Atomic.Read(Directory,"policy.bin",B,Used,Status); if Status/=OK then return; end if;
      if Used/=Size then Status:=Corrupt; return; end if;
      Decode(B,P,Status); if Status=OK then Fingerprint:=MC_SHA256.Hash(B); end if;
   end;
end MC_Site_Policy;
