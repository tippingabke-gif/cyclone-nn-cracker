"""Parse source and validate manifests without importing the runtime modules."""
import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import re


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'src')
    args = parser.parse_args()
    root = args.source_root.resolve()
    sources = sorted(root.rglob('*.py'))
    if not sources:
        raise ValueError('No Python sources found')
    for source in sources:
        ast.parse(source.read_text(encoding='utf-8-sig'), filename=source.name,
                  feature_version=(3, 10))

    entries = 0
    for variant in ('OPT', 'COM', 'MAX'):
        manifest = root / 'resources' / ('Runtime' + variant + 'Manifest.json')
        pairs = json.loads(manifest.read_text(encoding='utf-8-sig'),
                           object_pairs_hook=list)
        if not pairs:
            raise ValueError(f'Empty manifest: {manifest.name}')
        seen = set()
        for name, digest in pairs:
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or '..' in path.parts
                    or '\\' in name or ':' in name or name.casefold() in seen):
                raise ValueError(f'Invalid or duplicate manifest path: {name}')
            if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                raise ValueError(f'Invalid SHA-256 entry: {name}')
            seen.add(name.casefold())
            entries += 1
    print(f'Parsed {len(sources)} Python sources; validated 3 manifests ({entries} entries).')
    print('Runtime modules were not imported; engines were not started.')


if __name__ == '__main__':
    main()
