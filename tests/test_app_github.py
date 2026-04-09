import unittest

from app.github import GhAsset, github_pick_asset, parse_github_releases_payload


class GithubPickAssetTests(unittest.TestCase):
    def test_github_pick_asset_prefers_tar_over_bin(self) -> None:
        release = parse_github_releases_payload(
            [
                {
                    "tag_name": "v1.2.3",
                    "prerelease": False,
                    "assets": [
                        {"name": "firmware.bin", "browser_download_url": "https://example/bin", "size": 1},
                        {"name": "firmware.tar", "browser_download_url": "https://example/tar", "size": 2},
                    ],
                }
            ]
        )[0]

        asset = github_pick_asset(release)

        self.assertIsNotNone(asset)
        self.assertEqual(asset.name, "firmware.tar")

    def test_parse_github_releases_payload_ignores_non_firmware_assets(self) -> None:
        releases = parse_github_releases_payload(
            [
                {
                    "tag_name": "v1.2.3",
                    "prerelease": True,
                    "assets": [
                        {"name": "notes.txt", "browser_download_url": "https://example/txt", "size": 1},
                        {"name": "firmware.tar", "browser_download_url": "https://example/tar", "size": 2},
                    ],
                }
            ]
        )

        self.assertEqual(len(releases), 1)
        self.assertEqual(releases[0].tag, "v1.2.3")
        self.assertTrue(releases[0].prerelease)
        self.assertEqual(releases[0].assets, [GhAsset(name="firmware.tar", size=2, url="https://example/tar")])


if __name__ == "__main__":
    unittest.main()
