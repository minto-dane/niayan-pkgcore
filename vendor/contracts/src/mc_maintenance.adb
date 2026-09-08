-- SPDX-License-Identifier: MIT
package body MC_Maintenance with SPARK_Mode is
   function Valid (H : Hold) return Boolean is
     (H.Scope /= Zero_Identity and then H.Hold_ID /= Zero_Identity
      and then H.Policy /= Zero_Digest and then H.Subject /= Zero_Digest
      and then H.Reason /= Zero_Digest and then H.Serial > 0 and then H.Published_At > 0
      and then (H.Expires_At = 0 or else H.Expires_At > H.Published_At)
      and then (H.Blocks_Apply or else H.Blocks_Accept or else H.Blocks_Commit));
   function Valid (W : Window) return Boolean is
     (W.Scope /= Zero_Identity and then W.Window_ID /= Zero_Identity
      and then W.Policy /= Zero_Digest and then W.Change_Set /= Zero_Digest
      and then W.Not_Before > 0 and then W.Expires_At > W.Not_Before
      and then (not W.Emergency or else (W.Operations_Approved and then W.Security_Approved)));
   function Permits (W : Window; Now : Counter; Requested : Impact) return Boolean is
     (Valid (W) and then W.Not_Before <= Now and then Now < W.Expires_At
      and then Impact'Pos (Requested) <= Impact'Pos (W.Maximum_Impact));
   function Blocks (H : Hold; Subject : Digest; Apply, Accept_Change, Commit : Boolean) return Boolean is
     (Valid (H) and then H.Subject = Subject
      and then ((Apply and then H.Blocks_Apply) or else (Accept_Change and then H.Blocks_Accept)
        or else (Commit and then H.Blocks_Commit)));
end MC_Maintenance;
