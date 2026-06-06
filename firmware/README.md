# PX-W3PE firmware (`pxw3pe.fw`)

本ドライバ自体は、モデル固有の鍵バイトを1つも持っていません。probeのたびに
`/lib/firmware/pxw3pe.fw`から読み込む作りです。このディレクトリには、そのblobを
公式の`asv5220_dtv.ko`から作るためのツールが入っています。

## ビルド方法

```sh
python3 make_pxw3pe_fw.py --from-ko /path/to/asv5220_dtv.ko pxw3pe.fw
sudo cp pxw3pe.fw /lib/firmware/
```

`make_pxw3pe_fw.py`が組み立てるのは60バイトのblobです。中身は`PXWF`マジックと
バージョン、16バイトのauth文字列、それに4つの暗号フィールド。このうち暗号
フィールドだけは、手元の`.ko`から`extract/extract.sh`が抜き出します。

## 先に読むもの

詳しいことは`extract/README.md`に全部書いてあります。手順、前提条件、blobのレイアウト、
法的な注意、ハーネスの仕組み、注意点。まずはそっちから読んでください。

## ファイル一覧

| ファイル                | 内容                                                     |
|-----------------------|----------------------------------------------------------|
| `make_pxw3pe_fw.py`   | blob生成器（`--from-ko <driver.ko>`）                    |
| `extract/`            | 鍵抽出ハーネス（`extract/README.md`を参照）              |

4つの暗号フィールドはカードのモデルに固有の値で、ビルド時に手元の`.ko`から取り出します。こちらは
ここには置いていませんし、コミットも禁止です。
