-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Time_Guard with SPARK_Mode is
   function Fresh (S : Stamp; Boot : Identity; Now, Maximum_Age : Counter)
     return Boolean is
     (Boot /= Zero_Identity and then S.Boot_ID = Boot and then S.Sequence > 0
      and then Maximum_Age > 0 and then S.Observed_At <= Now
      and then S.Expires_At > Now and then S.Expires_At > S.Observed_At
      and then S.Expires_At - S.Observed_At <= Maximum_Age
      and then Now - S.Observed_At <= Maximum_Age);
   function Add_Bounded (Value, Increment : Counter) return Counter is
     (if Increment > Counter'Last - Value then Counter'Last else Value + Increment);
   function Elapsed (Now, Since, Duration : Counter) return Boolean is
     (Now >= Since and then Now - Since >= Duration);
end MC_Time_Guard;
