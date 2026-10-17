"""Native dispatch must not confuse host, container, ISA or configuration ABI."""

from __future__ import annotations

import unittest

from wmpf_mcp.platform.capabilities import analysis_module, hook_backend_supported


class BackendCapabilities(unittest.TestCase):
    def test_static_analysis_is_independent_of_host(self):
        self.assertEqual(analysis_module("Mach-O", "arm64"), "extractor")
        self.assertEqual(analysis_module("PE", "x86_64"), "windows")

    def test_different_host_cannot_reuse_native_hook(self):
        self.assertTrue(hook_backend_supported("darwin", "Mach-O", "arm64"))
        self.assertFalse(hook_backend_supported("win32", "Mach-O", "arm64"))

    def test_configuration_abi_must_match_when_supplied(self):
        self.assertTrue(hook_backend_supported("darwin", "Mach-O", "arm64", "darwin-arm64"))
        self.assertFalse(hook_backend_supported("darwin", "Mach-O", "arm64", "win64-legacy"))
        self.assertTrue(hook_backend_supported("win32", "PE", "x86_64", "win64-legacy"))
        self.assertFalse(hook_backend_supported("win32", "PE", "x86_64", "darwin-arm64"))
        self.assertFalse(hook_backend_supported("darwin", "PE", "x86_64", "win64-legacy"))

    def test_unimplemented_format_or_isa_cannot_become_ready(self):
        for platform, binary_format, arch in [("win32", "PE", "arm64"),
                                              ("darwin", "Mach-O", "x86_64"),
                                              ("linux", "ELF", "arm64")]:
            with self.subTest(platform=platform, binary_format=binary_format, arch=arch):
                self.assertIsNone(analysis_module(binary_format, arch))
                self.assertFalse(hook_backend_supported(platform, binary_format, arch))


if __name__ == "__main__":
    unittest.main()
