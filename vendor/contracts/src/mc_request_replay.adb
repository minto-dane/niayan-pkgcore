-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Request_Replay with SPARK_Mode is
   use type MC_Replay.Decision;
   procedure Consume (S : in out State; E : MC_Log_Format.Log_Entry;
                      Status : out Outcome) is
      N : State := S;
   begin
      Status := Corrupt;
      if S.Count = Counter'Last or else E.Sequence /= S.Count + 1
        or else E.Root_ID = Zero_Identity or else (S.Count > 0 and then E.Root_ID /= S.Root_ID)
        or else E.Generation < S.Serial
      then return; end if;
      if E.Kind = Genesis then
         if S.Count /= 0 or else E.Index /= 0 or else E.Operation_ID /= E.Root_ID
           or else E.Object = Zero_Digest or else E.Result /= OK
           or else E.Epoch /= 0 or else E.Token /= 0
         then return; end if;
         N.Last_Result := OK;
      elsif E.Kind = Begun then
         if E.Index = 0 or else E.Object = Zero_Digest or else E.Operation_ID = Zero_Identity
           or else E.Result /= OK
         then return; end if;
         if S.Window.Request_ID /= Zero_Identity and then
           MC_Replay.Check(S.Window,E.Epoch,E.Token,E.Index,E.Operation_ID,E.Object) /= MC_Replay.Fresh
         then return; end if;
         N.Pending := True; N.Last_Result := Indeterminate;
         N.Window := (E.Epoch,E.Token,E.Index,E.Operation_ID,E.Object);
      elsif E.Kind in Known_OK .. Unknown_Outcome then
         if not S.Pending or else E.Operation_ID /= S.Window.Request_ID
           or else E.Index /= S.Window.Sequence_Number or else E.Epoch /= S.Window.Epoch
           or else E.Token /= S.Window.Token or else E.Object /= S.Window.Request_Digest
         then return; end if;
         if (E.Kind = Known_OK and then E.Result /= OK)
           or else (E.Kind = Known_Failure and then E.Result in OK | Indeterminate)
           or else (E.Kind = Unknown_Outcome and then E.Result /= Indeterminate)
         then return; end if;
         N.Pending := E.Kind = Unknown_Outcome; N.Last_Result := E.Result;
      else return; end if;
      N.Count := S.Count + 1; N.Root_ID := E.Root_ID; N.Serial := E.Generation;
      S := N; Status := OK;
   end Consume;
end MC_Request_Replay;
