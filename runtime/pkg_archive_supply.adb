-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Authentic; with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix;
with Pkg_Deb_Metadata;
package body Pkg_Archive_Supply with SPARK_Mode => Off is
   use type Interfaces.C.unsigned; use type Wide;
   Magic : constant Bytes := (78, 73, 65, 83, 85, 80, 48, 49);
   Max_Integer : constant Counter := 2 ** 53 - 1;
   type Observation_Access is access Pkg_Deb_Metadata.Observation;
   procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Metadata.Observation, Observation_Access);
   procedure Check_Original (Store : in out MC_Store.Store;
      Receipt, Original, Control : Digest; Trusted : Authority;
      Now, Deadline : Counter; Historical : Boolean; Binding : out Digest; Status : out Outcome) is
      Wire : Bytes (1 .. Wire_Size); Used : Natural;
      Started, Finished, Epoch, Checked, Expires, Elapsed : Counter;
      Observed : Observation_Access := null;
      File : MC_FS.File;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Clock (Value : out Counter) is
      begin
         MC_Clock.Boottime_Milliseconds (Value, Status); Check;
         if Value >= Deadline then Status := Stale; raise Interrupted; end if;
      end Clock;
      procedure Present (Hash : Digest) is
      begin
         if Hash = Zero_Digest then Status := Corrupt; raise Interrupted; end if;
         Clock (Finished);
         MC_Store.Open_Object (Store, Hash, File, Status); Check; MC_FS.Close (File);
      end Present;
   begin
      Binding := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Receipt = Zero_Digest or else Original = Zero_Digest or else Control = Zero_Digest
        or else Trusted.Scope = Zero_Digest or else MC_Types.Is_Zero (Trusted.Key)
        or else Trusted.Minimum_Epoch not in 1 .. Max_Integer
        or else Trusted.Maximum_Age not in 1 .. Max_Lifetime
        or else Now not in 1 .. Max_Integer or else Deadline = Counter'Last then return; end if;
      Clock (Started);
      MC_Store.Read_Object (Store, Receipt, Wire, Used, Status); Check;
      Status := Corrupt;
      if Used /= Wire_Size then raise Interrupted; end if;
      if Wire (1 .. 8) /= Magic then Status := Unsupported; raise Interrupted; end if;
      if Wire (9 .. 40) /= Trusted.Scope or else Wire (73 .. 104) /= Original
        or else Wire (105 .. 136) /= Control then Status := Denied; raise Interrupted; end if;
      for I in 0 .. 2 loop
         if MC_Codec.U64 (Wire, 233 + 8 * I) not in 1 .. Wide (Max_Integer) then raise Interrupted; end if;
      end loop;
      Epoch := Counter (MC_Codec.U64 (Wire, 233)); Checked := Counter (MC_Codec.U64 (Wire, 241));
      Expires := Counter (MC_Codec.U64 (Wire, 249));
      if Expires <= Checked or else Expires - Checked > Max_Lifetime then raise Interrupted; end if;
      if Epoch < Trusted.Minimum_Epoch then Status := Denied; raise Interrupted; end if;
      if Checked > Now or else Now >= Expires or else Now - Checked > Trusted.Maximum_Age then
         Status := Stale; raise Interrupted;
      end if;
      MC_Authentic.Verify ("NiaOS/archive-supply/v1", Wire (1 .. Body_Size),
         Wire (Body_Size + 1 .. Wire_Size), Trusted.Key, Status); Check;
      for I in 0 .. 5 loop Present (Wire (41 + 32 * I .. 72 + 32 * I)); end loop;
      Observed := new Pkg_Deb_Metadata.Observation;
      Pkg_Deb_Metadata.Inspect (Store, Original, Deadline, Observed.all, Status); Check;
      if Observed.Original /= Original or else Observed.Control /= Control then
         Status := Conflict; raise Interrupted;
      end if;
      Clock (Finished);
      if Finished < Started then Status := Stale; raise Interrupted; end if;
      -- Ceiling without overflow; Now is a seconds observation taken at entry.
      Elapsed := (Finished - Started) / 1_000;
      if (Finished - Started) mod 1_000 /= 0 then Elapsed := Elapsed + 1; end if;
      if not Historical and then (Elapsed >= Expires - Now or else Elapsed > Trusted.Maximum_Age - (Now - Checked)) then
         Status := Stale; raise Interrupted;
      end if;
      Binding := Receipt; Status := OK; Free (Observed);
   exception
      when Interrupted => MC_FS.Close (File); Free (Observed); Binding := Zero_Digest;
      when Storage_Error => MC_FS.Close (File); Free (Observed); Binding := Zero_Digest; Status := Exhausted;
      when others => MC_FS.Close (File); Free (Observed); Binding := Zero_Digest; Status := Indeterminate;
   end Check_Original;
   procedure Verify_Original (Store : in out MC_Store.Store;
      Receipt, Original, Control : Digest; Trusted : Authority;
      Now, Deadline : Counter; Binding : out Digest; Status : out Outcome) is
   begin
      Check_Original (Store, Receipt, Original, Control, Trusted, Now, Deadline, False, Binding, Status);
   end Verify_Original;
   procedure Recheck_Original (Store : in out MC_Store.Store;
      Receipt, Original, Control : Digest; Trusted : Authority;
      Observed_At, Deadline : Counter; Binding : out Digest; Status : out Outcome) is
   begin
      Check_Original (Store, Receipt, Original, Control, Trusted, Observed_At, Deadline, True, Binding, Status);
   end Recheck_Original;
end Pkg_Archive_Supply;
