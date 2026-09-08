-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Time_Guard with SPARK_Mode, Pure is
   type Stamp is record
      Boot_ID : Identity := Zero_Identity;
      Sequence, Observed_At, Expires_At : Counter := 0;
   end record;
   function Fresh (S : Stamp; Boot : Identity; Now, Maximum_Age : Counter)
     return Boolean with Global => null,
       Post => (if Fresh'Result then
         Boot /= Zero_Identity and then S.Boot_ID = Boot
         and then S.Sequence > 0 and then Maximum_Age > 0
         and then S.Observed_At <= Now and then S.Expires_At > Now
         and then S.Expires_At - S.Observed_At <= Maximum_Age
         and then Now - S.Observed_At <= Maximum_Age);
   function Add_Bounded (Value, Increment : Counter) return Counter
     with Global => null,
       Post => Add_Bounded'Result >= Value;
   function Elapsed (Now, Since, Duration : Counter) return Boolean
     with Global => null;
   -- Receiver-local CLOCK_BOOTTIME only. Remote monotonic timestamps must be
   -- converted by a qualified receiver observation, never compared directly.
end MC_Time_Guard;
