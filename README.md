# readelf-py
readelfをPythonで書き直したものです。

## 使い方
別途インストールするライブラリはありません。
```
$ python3 readelf.py [-h] [-eh] [-l] [-S] [-e] [-s] [--export PATH] file
```

## オプション
```
必須引数:
  file                  ELFファイル
オプション:
  -h, --help            ヘルプを表示
  -eh, --file-header     ELFヘッダを表示
  -l, --program-headers  プログラムヘッダを表示
  -S, --section-headers  セクションヘッダを表示
  -e, --headers          ヘッダをすべて表示
  -s, --symbol          シンボルテーブルを表示
  --export PATH         結果をjsonで出力するときのパス
```