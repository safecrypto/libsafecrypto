function [huffman, tree] = huffman(bits, sig)
depth = 2^bits;
d = 1 / (sqrt(2 * pi) * sig);
e = -0.5 / (sig * sig);
p(1:depth) = d * exp(e * [0:depth-1].^2);

nodes = num2cell(1:depth);
probs = p;

while length(nodes) > 1
  [mn, idx] = min(probs);
  probs(idx) = Inf;
  [mn2, idx2] = min(probs);
  probs(idx) = mn + mn2;
  probs(idx2) = [];
  nodes{idx} = {nodes{idx}, nodes{idx2}};
  nodes(idx2) = [];
end

codes = cell(size(p));
codes = huffman_codes('', nodes{1}, codes);
tree = [];
tree = huffman_tree(nodes{1}, tree);

lengths = cellfun(@length, codes);

huffman = cell(length(lengths),2);
for i=1:length(lengths)
   huffman{i,1} = codes{i};
   huffman{i,2} = lengths(i);
end

fprintf('// Generated from Matlab/Octave using %d bits and sigma=%f\n', bits, sig);
fprintf('static const huffman_code_t huff_code_gaussian_%d[] = {\n', bits);
for i=1:length(lengths)
    fprintf('    { 0x%08X, %4d },\n', bin2dec(huffman{i,1}), huffman{i,2});
end
fprintf('};\n');

fprintf('static const huffman_node_t huff_node_gaussian_%d[] = {\n', bits);
for i=1:size(tree,1)
    fprintf('    {%4d, %4d, %4d },\n', tree(i,1), tree(i,2), tree(i,3));
end
fprintf('};\n');

fprintf('static const huffman_table_t huff_table_gaussian_%d[] = {\n', bits);
fprintf('    huff_code_gaussian_%d, huff_node_gaussian_%d, %d\n', bits, bits, depth);
fprintf('};\n\n');


function tree = huffman_tree(nodes, tree)
if length(nodes) == 1
    tuple = [-1,-1,nodes-1];
    tree = [tree; tuple];
    return;
else
    tuple = [-1,-1,-1];
    tree = [tree; tuple];
    idx = size(tree,1);
    tree(idx,1) = size(tree,1);
    tree = huffman_tree(nodes{1}, tree);
    tree(idx,2) = size(tree,1);
    tree = huffman_tree(nodes{2}, tree);
end


function codes = huffman_codes(cur_code, nodes, codes)
if length(nodes) == 1
    symbol = nodes;
    codes{symbol} = cur_code;
    return;
else
    codes = huffman_codes([cur_code, '0'], nodes{1}, codes);
    codes = huffman_codes([cur_code, '1'], nodes{2}, codes);
end



