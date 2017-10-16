function dist = huffman_sampler(tree, n)
num = n;
dist = [];
while num > 0
    node = 1;
    while tree(node,3) == -1
        rnd = unidrnd(2);
        node = (rnd == 1) * tree(node,1) + (rnd == 2) * tree(node,2) + 1;
    end
    dist = [dist; tree(node,3)];
    num = num - 1;
end
