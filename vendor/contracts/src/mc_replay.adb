-- SPDX-License-Identifier: MIT
package body MC_Replay with SPARK_Mode is
   function Check
     (State : Window; Epoch, Token, Sequence_Number : Counter;
      Request_ID : Identity; Request_Digest : Digest) return Decision is
   begin
      if Epoch = 0 or else Token = 0 or else Sequence_Number = 0
        or else Is_Zero (Request_ID) or else Is_Zero (Request_Digest)
      then return Reject_Invalid; end if;
      if Epoch < State.Epoch or else Token < State.Token then return Reject_Stale; end if;
      if Epoch = State.Epoch and then Token = State.Token then
         if Sequence_Number < State.Sequence_Number then return Reject_Stale; end if;
         if Sequence_Number = State.Sequence_Number then
            if Request_ID = State.Request_ID and then Request_Digest = State.Request_Digest then
               return Exact_Retry;
            else return Reject_Conflict; end if;
         end if;
         if Request_ID = State.Request_ID then return Reject_Conflict; end if;
         if State.Sequence_Number = Counter'Last
           or else Sequence_Number /= State.Sequence_Number + 1
         then return Reject_Stale; end if;
      else
         if Token <= State.Token or else Sequence_Number /= 1 then
            return Reject_Stale;
         end if;
      end if;
      return Fresh;
   end Check;
   procedure Record_Request
     (State : in out Window; Epoch, Token, Sequence_Number : Counter;
      Request_ID : Identity; Request_Digest : Digest; Result : out Decision) is
   begin
      Result := Check (State, Epoch, Token, Sequence_Number, Request_ID, Request_Digest);
      if Result = Fresh then
         State := (Epoch, Token, Sequence_Number, Request_ID, Request_Digest);
      end if;
   end Record_Request;
end MC_Replay;
