from __future__ import absolute_import, division, print_function
import argparse
import logging
import os
import torch
from torch.utils.data import DataLoader, Dataset, SequentialSampler
from transformers import T5ForConditionalGeneration, RobertaTokenizer
from tqdm import tqdm
import pandas as pd

# ROOT_DIR = '/mnt/local/conti/VulRepair'
ROOT_DIR = './'

cpu_cont = 16
logger = logging.getLogger(__name__)

class InputFeatures(object):
    """A single training/auto_patch features for a example."""
    def __init__(self, input_ids):
        self.input_ids = input_ids


class Code4Repair(Dataset):
    def __init__(self, tokenizer, args):
        
        # example_file = os.path.join(ROOT_DIR, 'data/demo_conti.csv')
        example_file = os.path.join(ROOT_DIR, args.vuln_path)

        sources = pd.read_csv(example_file)['source'].tolist()
        print(f"Load vuln data from csv file: {example_file}, len = {len(sources)}")
        # sources = sources[:8]
        # print("truncated data to:", len(sources))
        
        self.examples = []
        for i in tqdm(range(len(sources))):
            self.examples.append(convert_examples_to_features(sources[i], tokenizer, args))

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, i):       
        return self.examples[i].input_ids, self.examples[i].input_ids.ne(0)

def convert_examples_to_features(source, tokenizer, args):
    # encode - subword tokenize
    source_ids = tokenizer.encode(source, truncation=True, max_length=args.encoder_block_size, padding='max_length', return_tensors='pt')
    return InputFeatures(source_ids)


def clean_tokens(tokens):
    tokens = tokens.replace("<pad>", "")
    tokens = tokens.replace("<s>", "")
    tokens = tokens.replace("</s>", "")
    tokens = tokens.strip("\n")
    tokens = tokens.strip()
    tokens = tokens.replace("<S2SV_ModStart>", "")
    tokens = tokens.replace("<S2SV_ModEnd>", "")
    tokens = tokens.replace("<S2SV_blank>", "")
    toekns = tokens.replace("<S2SV_null>", "")
    return tokens

def auto_patch(args, model, tokenizer, vuln4repair):
    # build dataloader
    vulns_sampler = SequentialSampler(vuln4repair)
    vulns_dataloader = DataLoader(vuln4repair, sampler=vulns_sampler, batch_size=args.eval_batch_size, num_workers=0)
    # multi-gpu evaluate
    if args.n_gpu > 1:
        model = torch.nn.DataParallel(model)
    # Running!
    logger.info("***** Running AutoPatch *****")
    logger.info("  Num vulns = %d", len(vuln4repair))
    logger.info("  Batch size = %d", args.eval_batch_size)
    
    model.eval()
    
    results = []

    bar = tqdm(vulns_dataloader, total=len(vulns_dataloader))
    for batch in bar:
        (input_ids, attention_mask)=[x.squeeze(1).to(args.device) for x in batch]
        with torch.no_grad():
            beam_outputs = model.generate(input_ids=input_ids,
                                          attention_mask=attention_mask,
                                          do_sample=False, # disable sampling to auto_patch if batching affects output
                                          num_beams=args.num_beams,
                                          num_return_sequences=args.num_beams,
                                          max_length=args.decoder_block_size)
        beam_outputs = beam_outputs.detach().cpu().tolist()

        # The batch size is not 1, so we need to iterate over the batch
        # Iterate over each input in the batch
        for index, input_id in enumerate(input_ids):
            vuln_code = tokenizer.decode(input_id, skip_special_tokens=True)
            # Calculate the starting and ending indices of the beams for the current input
            start_index = index * args.num_beams
            end_index = start_index + args.num_beams

            # Get all beam outputs for the current input and clean them
            for beam_index in range(start_index, end_index):
                prediction = tokenizer.decode(beam_outputs[beam_index], skip_special_tokens=False)
                clean_prediction = clean_tokens(prediction)
                print(clean_prediction)
                results.append({"vuln_code": vuln_code, "fix_code": clean_prediction})
                
    # save the results for each vuln_code according to the num_beams
    results_df = pd.DataFrame(results)
            
    ## save the corresponding vuln_code and fix_code into csv file
    save_dir = os.path.join(ROOT_DIR, args.output_dir)
    os.makedirs(save_dir, exist_ok=True)
    results_df.to_csv(os.path.join(save_dir, "vuln_fix_pairs.csv"), index=False)
        

def main():
    parser = argparse.ArgumentParser()

    # Params
    parser.add_argument("--model_path", default=None, type=str, required=False,
                        help="The path to the model checkpoint for inference. If not specified, we will use the pretrained model from Huggingface.")
    
    parser.add_argument("--vuln_path", default="data/demo_conti.csv", type=str,
                        help="Path to the input dataset for auto_patch, which is a csv file with a column named 'source' containing the vulnerable code snippets.")
                        
    parser.add_argument("--output_dir", default="autopatch_results", type=str, required=False,
                        help="The output directory where the model predictions and checkpoints will be written.")
    
    parser.add_argument("--eval_batch_size", default=1, type=int, required=False,
                        help="Batch size per GPU/CPU for evaluation.")
    
    parser.add_argument("--encoder_block_size", default=512, type=int,
                        help="Optional input sequence length after tokenization."
                             "Default to the model max input length for single sentence inputs (take into account special tokens).")
    
    parser.add_argument("--decoder_block_size", default=256, type=int,
                        help="Optional input sequence length after tokenization."
                             "Default to the model max input length for single sentence inputs (take into account special tokens).")
    
    parser.add_argument("--num_beams", default=1, type=int,
                        help="Beam size to use when decoding.") 
    
    parser.add_argument("--config_name", default="", type=str,
                        help="Optional pretrained config name or path.")
    


    args = parser.parse_args()

    # Setup CUDA, GPU
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    args.n_gpu = 1
    args.device = device

    # Setup logging
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(name)s -   %(message)s',datefmt='%m/%d/%Y %H:%M:%S',level=logging.INFO)
    logger.warning("device: %s, n_gpu: %s",device, args.n_gpu,)

    tokenizer = RobertaTokenizer.from_pretrained('MickyMike/VulRepair')
    tokenizer.add_tokens(["<S2SV_StartBug>", "<S2SV_EndBug>", "<S2SV_blank>", "<S2SV_ModStart>", "<S2SV_ModEnd>"])
    model = T5ForConditionalGeneration.from_pretrained('MickyMike/VulRepair') 
    model.resize_token_embeddings(len(tokenizer))

    logger.info("Running AUtoPatch with parameters %s", args)

    # Evaluation
    results = {}  
    
    if args.model_path:
        checkpoint_prefix = f'model.bin'
        model_path = os.path.join(args.model_path, '{}'.format(checkpoint_prefix))  
        model.load_state_dict(torch.load(model_path, map_location=args.device))
    
    model.to(args.device)
    vuln4repair = Code4Repair(tokenizer, args)
    auto_patch(args, model, tokenizer, vuln4repair)
    return results

if __name__ == "__main__":
    main()
