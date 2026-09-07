-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Time_Guard with SPARK_Mode, Pure is
   type Stamp is record
      Boot_ID : Identity := Zero_Identity;
      Sequence, Observed_At, Expires_At : Counter := 0;
   end record;
   function Fresh (S : Stamp; Boot : Identity; Now, Maximum_Age : Counter)
     return Boolean with Global => null;
   function Add_Bounded (Value, Increment : Counter) return Counter
     with Global => null,
       Post => Add_Bounded'Result >= Value;
   function Elapsed (Now, Since, Duration : Counter) return Boolean
     with Global => null;
   -- Receiver-local CLOCK_BOOTTIME only. Remote monotonic timestamps must be
   -- converted by a qualified receiver observation, never compared directly.
end MC_Time_Guard;
