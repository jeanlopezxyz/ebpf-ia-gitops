package qos

import "math"

// QoSCalculator provides methods for calculating Quality of Service metrics
type QoSCalculator struct{}

// NewQoSCalculator creates a new QoS calculator
func NewQoSCalculator() *QoSCalculator {
	return &QoSCalculator{}
}

// CalculateMean calculates the arithmetic mean of values
func (q *QoSCalculator) CalculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// CalculateMax finds the maximum value
func (q *QoSCalculator) CalculateMax(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}

// CalculateMin finds the minimum value
func (q *QoSCalculator) CalculateMin(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}
	return min
}

// CalculateJitter calculates jitter as variance in latency
func (q *QoSCalculator) CalculateJitter(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	
	mean := q.CalculateMean(values)
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(values))
	return math.Sqrt(variance)  // Standard deviation as jitter
}

// CalculatePercentile calculates the specified percentile
func (q *QoSCalculator) CalculatePercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	// Simple percentile calculation (could be optimized)
	sorted := make([]float64, len(values))
	copy(sorted, values)
	
	// Basic bubble sort for simplicity
	for i := 0; i < len(sorted); i++ {
		for j := 0; j < len(sorted)-1-i; j++ {
			if sorted[j] > sorted[j+1] {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}
	
	index := int(percentile * float64(len(sorted)-1))
	return sorted[index]
}