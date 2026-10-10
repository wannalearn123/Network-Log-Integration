# ML experiments dropped

The supported runtime is rules-only. The previous training and inference code
was removed because its dataset flow features did not have a validated equivalent
in the live syslog window. No model is loaded by the detector.

Before promoting ML into the runtime:

1. Define features with identical semantics in training and serving. Dataset
   flow counters and duration are not interchangeable with syslog window counts.
2. Split by time/session before fitting preprocessing or selecting features.
3. Evaluate on labelled logs from the actual deployment, including benign bursts.
4. Calibrate thresholds, record dataset/schema/library versions, and test the
   entire feature contract.
5. Replace the script with a CLI and remove the unreachable ablation experiment.

Future ML work must be designed and evaluated separately before being added back.
This directory intentionally contains documentation only.
