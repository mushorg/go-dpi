#include <stdio.h>
#include <stdlib.h>
#include <linear.h>

extern int predict_2grams(struct model *_model, int *indexes, float *values, int no_grams, float *confidence) {
    int n, i, j;
    double predict_label;
    double *probabilities;
    int nr_class = get_nr_class(_model);
    int nr_feature = get_nr_feature(_model);

    if(_model->bias >= 0) {
        n = nr_feature+1;
    } else {
        n = nr_feature;
    }

    struct feature_node *nodes = (struct feature_node*) malloc(no_grams * sizeof(struct feature_node));

    // set node values
    for (i = 0; i < no_grams; i++) {
        nodes[i].index = indexes[i];
        nodes[i].value = values[i];
    }

    // set bias if available
    if (_model->bias >= 0) {
        nodes[i].index = n;
        nodes[i].value = _model->bias;
        i++;
    }

    // set nodes terminator value
    nodes[i].index = -1;

    // predict label
    probabilities = (double*) malloc(nr_class * sizeof(double));
    predict_label = predict_probability(_model, nodes, probabilities);
    free(nodes);

    // find predicted label confidence
    int *labels = (int*) malloc(nr_class * sizeof(int));
    get_labels(_model, labels);

    // print labels and probabilities
    #ifdef DEBUG
    printf("\n%g\t\t", predict_label);
    for (j = 0; j < _model->nr_class; j++)
        printf("\t%g", probabilities[j]);
    printf("\n");
    printf("labels\t\t");
    for (j = 0; j < nr_class; j++) {
        printf("\t\t%d", labels[j]);
    }
    printf("\n");
    fflush(stdout);
    #endif

    // set confidence to detected label's probability
    for (j = 0; j < nr_class; j++) {
        if (labels[j] == predict_label) {
            *confidence = probabilities[j];
        }
    }

    free(labels);
    free(probabilities);

    return predict_label;
}
