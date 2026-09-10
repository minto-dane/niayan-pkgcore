-- SPDX-License-Identifier: BSD-3-Clause
with MC_Protocol; with MC_SHA256;
package body MC_Ingress with SPARK_Mode => Off is
   use type MC_Replay.Decision;
   procedure Check_Request
     (Raw_Header, Body_Data : Bytes; Sig : MC_Signatures.Signature;
      Key : MC_Signatures.Public_Key; Scope : MC_Authorization.Scope;
      Expected_Contract : Digest; Now : Counter; Previous : MC_Replay.Window;
      Candidate : out MC_Replay.Window; Request : out MC_Requests.Request;
      Classification : out MC_Replay.Decision; Status : out Outcome) is
      Verified : MC_Signatures.Verified_Message;
      H : MC_Protocol.Header;
      Parsed : MC_Requests.Request;
   begin
      Candidate := Previous; Request := (others=><>);
      Classification := MC_Replay.Reject_Invalid;
      MC_Signatures.Verify(Raw_Header,Body_Data,Sig,Key,Verified,Status);
      if Status/=OK then return; end if;
      H := MC_Signatures.Content(Verified);
      Status := Denied;
      if not MC_Authorization.Within_Scope(H,Scope,Now) then return; end if;
      MC_Requests.Decode(Body_Data,Parsed,Status);
      if Status/=OK then return; end if;
      Status := Denied;
      if Is_Zero(Expected_Contract) or else Parsed.Contract_Digest /= Expected_Contract
        or else not MC_Requests.Header_Binds(H,Parsed)
      then return; end if;
      MC_Replay.Record_Request(Candidate,H.Membership_Epoch,H.Fence_Token,H.Sequence_Number,
                              H.Request_ID,MC_SHA256.Hash(Raw_Header),Classification);
      if Classification not in MC_Replay.Fresh | MC_Replay.Exact_Retry then return; end if;
      Request := Parsed; Status := OK;
   end Check_Request;
end MC_Ingress;
