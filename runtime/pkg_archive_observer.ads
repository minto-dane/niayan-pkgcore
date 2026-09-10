-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Archive_Supply;
package Pkg_Archive_Observer with SPARK_Mode => Off is
   Maximum_Policy : constant := 5 * 1024 * 1024;
   procedure Observe (Store : in out MC_Store.Store; Request_ID : Digest;
      Original, Control, InRelease, Index, Keyring : Digest;
      Index_Path, Deb_Path : String; Observer_UID : Word;
      Trusted : Pkg_Archive_Supply.Authority; Deadline : Counter;
      Receipt, Policy : out Digest; Status : out Outcome);
   -- Caller retains the open Store's writer reservation throughout. All five
   -- original objects must already be retained; only borrowed read FDs cross
   -- the fixed internal socket. This never reopens/unlocks the CAS reservation.
   -- Observer_UID and Trusted come from independent site configuration, not the
   -- response or request. Native signature, exact original hashes and current
   -- UTC are verified before returning the receipt address. Policy/receipt are
   -- saved using the existing Store; failures clear both output digests but may
   -- leave unreferenced objects or an advanced independent TUF checkpoint.
   -- Deadline is an exclusive BOOTTIME millisecond bound, at most 130 seconds
   -- from entry. No retry, generation pin, installed-state change or execution
   -- permit occurs. Caller must reobserve current site trust and bind the result
   -- into the full supply map and all managed admission guards before use.
end Pkg_Archive_Observer;
