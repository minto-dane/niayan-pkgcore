-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body MC_Requests with SPARK_Mode is
   use type Byte; use type Wide; use type MC_Protocol.Message_Kind;
   function Encode (R : Request) return Request_Bytes is
      B : Request_Bytes := (others=>0);
   begin
      B(1..4) := (16#4D#,16#43#,16#4F#,16#32#);
      MC_Codec.Put16(B,5,2); B(7) := Byte(Requested_Action'Pos(R.Action)+1);
      B(9..24) := R.Transaction_ID; B(25..56) := R.Plan_Digest;
      B(57..88) := R.Contract_Digest;
      MC_Codec.Put64(B,89,Wide(R.Expected_Revision));
      MC_Codec.Put64(B,97,Wide(R.Base_Generation));
      B(105..136) := R.Stage_Set_Digest; B(137..168) := R.Evidence_Digest;
      return B;
   end Encode;
   procedure Decode (Data : Bytes; R : out Request; Status : out Outcome) is
      B : Request_Bytes;
   begin
      R := (others=><>); Status := Invalid_Input;
      if Data'Length/=Body_Size then return; end if;
      B := Data;
      if B(1..4)/=Bytes'(16#4D#,16#43#,16#4F#,16#32#)
        or else MC_Codec.U16(B,5)/=2 or else B(8)/=0
        or else B(7) not in 1..9 or else not Is_Zero(B(169..192))
        or else MC_Codec.U64(B,89)>Wide(Counter'Last)
        or else MC_Codec.U64(B,97)>Wide(Counter'Last)
      then return; end if;
      R.Action := Requested_Action'Val(Integer(B(7))-1);
      R.Transaction_ID := B(9..24); R.Plan_Digest := B(25..56);
      R.Contract_Digest := B(57..88);
      R.Expected_Revision := Counter(MC_Codec.U64(B,89));
      R.Base_Generation := Counter(MC_Codec.U64(B,97));
      R.Stage_Set_Digest := B(105..136); R.Evidence_Digest:=B(137..168);
      if Is_Zero(R.Transaction_ID) or else Is_Zero(R.Plan_Digest)
        or else Is_Zero(R.Contract_Digest)
      then return; end if;
      if R.Action in Prepare | Apply and then Is_Zero(R.Stage_Set_Digest) then return; end if;
      if R.Action in Commit | Restore and then Is_Zero(R.Evidence_Digest) then return; end if;
      Status := OK;
   end Decode;
   function Header_Binds (H : MC_Protocol.Header; R : Request) return Boolean is
      Expected : MC_Protocol.Message_Kind;
   begin
      case R.Action is
         when Plan => Expected := MC_Protocol.Plan_Request;
         when Prepare => Expected := MC_Protocol.Prepare_Request;
         when Apply => Expected := MC_Protocol.Apply_Request;
         when Inspect => Expected := MC_Protocol.Inspect_Request;
         when Recover => Expected := MC_Protocol.Recover_Request;
         when Commit => Expected := MC_Protocol.Commit_Request;
         when Restore => Expected := MC_Protocol.Restore_Request;
         when Reconcile => Expected := MC_Protocol.Reconcile_Request;
         when Repair => Expected := MC_Protocol.Repair_Request;
      end case;
      return H.Kind=Expected and then H.Body_Length=Body_Size
        and then H.Body_Digest=MC_SHA256.Hash(Encode(R));
   end Header_Binds;
end MC_Requests;
