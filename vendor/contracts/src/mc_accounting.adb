-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Accounting with SPARK_Mode is
   function Valid (E : Event) return Boolean is
     (E.Event_ID/=Zero_Identity and then E.Scope/=Zero_Identity and then E.Object_ID/=Zero_Identity
      and then E.Actor/=Zero_Identity and then E.Correlation_ID/=Zero_Identity
      and then E.Payload/=Zero_Digest and then E.Policy/=Zero_Digest and then E.Sequence>0
      and then E.Observed_At>0 and then E.Trust_Epoch>0 and then E.Authenticated
      and then (if E.Sequence=1 then E.Previous_Record=Zero_Digest else E.Previous_Record/=Zero_Digest));
   function Chain_Extends (Previous_Digest : Digest; Previous_Sequence : Counter; E : Event) return Boolean is
     (Valid(E) and then Previous_Sequence<Counter'Last and then E.Sequence=Previous_Sequence+1
      and then E.Previous_Record=Previous_Digest);
   function Required_Remote_Preservation (E : Event) return Boolean is
     (E.Level in Security | Critical or else E.Kind in Breakglass_Requested | Breakglass_Authorized |
      Node_Fenced | Trust_Rotated | Security_Denial | Policy_Changed);
end MC_Accounting;
